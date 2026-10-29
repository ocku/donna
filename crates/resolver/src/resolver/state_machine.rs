#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

mod candidates;
mod round;
mod startup;

use std::{
    collections::HashMap,
    net::SocketAddr,
    ops::ControlFlow,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use dns::{DomainName, Question};
use tracing::{debug, warn};
use transport::Transport;

use crate::{
    ResolutionCacheSource, ResolveError,
    name::NameSet,
    protocol::{is_usable_response, query_with_algorithm_signals},
    response::{consume_work, schedule_retries},
};

use super::{
    AlgorithmSignals, ResolutionOutcome, ResolutionStatsContext, Resolver,
    address::PendingNameServer,
    cache::CachedResolution,
    cache::dname::traversal::{CachedDnameContext, CachedDnameProgress},
    response_handling::{ProofDeadlines, ResponseAction, ResponseContext},
};

pub(super) struct ResolutionState<'resolver> {
    pub(super) active_question: Question,
    pub(super) cname_answers: Vec<dns::ResourceRecord>,
    pub(super) cname_authorities: Vec<dns::ResourceRecord>,
    pub(super) proof_deadlines: ProofDeadlines,
    pub(super) cname_names: NameSet,
    pub(super) current_delegation_zone: DomainName,
    pub(super) candidates: Vec<SocketAddr>,
    pub(super) pending_name_servers: Vec<PendingNameServer<'resolver>>,
    pub(super) restart_from_root: bool,
    pub(super) zone_attempted: bool,
    pub(super) address_lookup: bool,
    pub(super) bootstraps: Vec<(DomainName, Question)>,
    pub(super) recovery: Vec<super::delegation_recovery::RecoveryAttempt>,
    pub(super) attempts: Arc<Mutex<super::retry_budget::RetryBudget>>,
    pub(super) reachable_dns_error: bool,
    pub(super) cname_loop_seen: bool,
    pub(super) deferred_address_error: Option<ResolveError>,
    pub(super) used_cached_delegation: bool,
    pub(super) algorithm_signals: Arc<AlgorithmSignals>,
    pub(super) cache_allowed: bool,
    pub(super) validated_dnames_allowed: bool,
}

struct ResolutionSeed {
    active_question: Question,
    cname_answers: Vec<dns::ResourceRecord>,
    cname_authorities: Vec<dns::ResourceRecord>,
    cname_names: NameSet,
}

impl ResolutionState<'_> {
    fn new(
        seed: ResolutionSeed,
        address_lookup: bool,
        algorithm_signals: Arc<AlgorithmSignals>,
        cache_allowed: bool,
        validated_dnames_allowed: bool,
    ) -> Self {
        let ResolutionSeed {
            active_question,
            cname_answers,
            cname_authorities,
            cname_names,
        } = seed;
        Self {
            active_question,
            cname_answers,
            cname_authorities,
            proof_deadlines: ProofDeadlines::default(),
            cname_names,
            current_delegation_zone: DomainName::root(),
            candidates: Vec::new(),
            pending_name_servers: Vec::new(),
            restart_from_root: false,
            zone_attempted: false,
            address_lookup,
            bootstraps: Vec::new(),
            recovery: Vec::new(),
            attempts: Arc::new(Mutex::new(super::retry_budget::RetryBudget::default())),
            reachable_dns_error: false,
            cname_loop_seen: false,
            deferred_address_error: None,
            used_cached_delegation: false,
            algorithm_signals,
            cache_allowed,
            validated_dnames_allowed,
        }
    }
}

impl<T: Transport> Resolver<T> {
    pub(super) async fn resolve_inner(
        &self,
        question: Question,
        resolving_ns_hosts: Vec<DomainName>,
        remaining_steps: Arc<AtomicUsize>,
        stats: ResolutionStatsContext,
        algorithm_signals: Arc<AlgorithmSignals>,
        use_validated_dnames: bool,
    ) -> Result<ResolutionOutcome, ResolveError> {
        let cache_allowed = self.config.trust_anchors.is_empty();
        let address_lookup = !resolving_ns_hosts.is_empty();
        let validated_dnames_allowed = !cache_allowed
            && use_validated_dnames
            && !algorithm_signals.checking_disabled
            && !address_lookup;
        let seed = match self
            .seed_resolution(
                &question,
                address_lookup,
                algorithm_signals.checking_disabled,
                cache_allowed,
            )
            .await?
        {
            ControlFlow::Break(outcome) => return Ok(outcome),
            ControlFlow::Continue(seed) => seed,
        };
        let mut state = ResolutionState::new(
            seed,
            address_lookup,
            algorithm_signals,
            cache_allowed,
            validated_dnames_allowed,
        );
        if let Some(outcome) = self
            .prepare_resolution(&question, &remaining_steps, &stats, &mut state)
            .await?
        {
            return Ok(outcome);
        }
        self.run_resolution(
            &question,
            &resolving_ns_hosts,
            remaining_steps,
            stats,
            state,
        )
        .await
    }

    async fn run_resolution<'resolver>(
        &'resolver self,
        question: &Question,
        resolving_ns_hosts: &[DomainName],
        remaining_steps: Arc<AtomicUsize>,
        stats: ResolutionStatsContext,
        mut state: ResolutionState<'resolver>,
    ) -> Result<ResolutionOutcome, ResolveError> {
        loop {
            if remaining_steps.load(Ordering::Relaxed) == 0
                && !state
                    .pending_name_servers
                    .iter()
                    .any(PendingNameServer::is_suspended)
            {
                break;
            }
            self.prepare_resolution_candidates(
                resolving_ns_hosts,
                &remaining_steps,
                &stats,
                &mut state,
            )
            .await?;
            // Take up to `max_concurrent_queries` candidates in pop order and
            // race them; the first usable reply wins and the rest are dropped.
            let mut batch = Vec::new();
            while batch.len() < self.config.max_concurrent_queries.max(1)
                && let Some(server) = state.candidates.pop()
            {
                batch.push(server);
            }
            if batch.is_empty() {
                continue;
            }
            match self
                .run_resolution_round(
                    question,
                    resolving_ns_hosts,
                    &remaining_steps,
                    &stats,
                    &mut state,
                    &batch,
                )
                .await?
            {
                RoundProgress::Continue => {}
                RoundProgress::WorkExhausted => break,
                RoundProgress::Complete(outcome) => return Ok(outcome),
            }
        }

        warn!(
            max_steps = self.config.max_steps,
            "DNS resolution exceeded work limit"
        );
        Err(ResolveError::WorkLimitExceeded)
    }
}

enum RoundProgress {
    Continue,
    WorkExhausted,
    Complete(ResolutionOutcome),
}

impl<T: Transport> Resolver<T> {}

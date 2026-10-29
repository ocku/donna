use std::sync::{Arc, atomic::AtomicUsize};

use dns::DomainName;
use tracing::debug;
use transport::Transport;

use crate::{protocol::Referral, response::delegation_progresses};

use super::{
    ResolutionStatsContext, Resolver, address::PendingNameServer, state_machine::ResolutionState,
};

impl<T: Transport> Resolver<T> {
    pub(super) async fn follow_referral<'resolver>(
        &'resolver self,
        referral: Referral,
        observed_at: std::time::Instant,
        resolving_ns_hosts: &[DomainName],
        remaining_steps: Arc<AtomicUsize>,
        stats: ResolutionStatsContext,
        state: &mut ResolutionState<'resolver>,
    ) -> Result<bool, crate::ResolveError> {
        // A DS lookup must never cross into the queried child's namespace.
        // Authenticated no-DS referrals complete before this point; an
        // unproven referral is unusable rather than a reason to query the child.
        if state.active_question.qtype == dns::QueryType::DS
            && referral.zone.eq_dns(&state.active_question.qname)
        {
            return Ok(false);
        }
        if !delegation_progresses(&state.current_delegation_zone, &referral.zone) {
            debug!(
                current_zone = ?state.current_delegation_zone,
                referral_zone = ?referral.zone,
                "discarding non-progressing DNS referral"
            );
            return Ok(false);
        }

        self.insert_delegation_backend(&referral, observed_at)
            .await?;
        state.pending_name_servers.clear();
        let mut candidates = if referral.candidates.is_empty() {
            let resolution = self
                .resolve_name_server_addresses(
                    &referral.name_servers,
                    resolving_ns_hosts,
                    remaining_steps,
                    stats.clone(),
                    Arc::clone(&state.algorithm_signals),
                )
                .await;
            if let Some(error) = resolution.error {
                if super::address::deferred_address_error(&error) {
                    state.deferred_address_error.get_or_insert(error);
                    return Ok(false);
                }
                return Err(error);
            }
            state.pending_name_servers = resolution.pending_name_servers;
            resolution.addresses
        } else {
            // Glue is only a starting set. Resolve every NS name if it fails so
            // changed addresses for initially glued servers remain reachable.
            state.pending_name_servers = referral
                .name_servers
                .iter()
                .cloned()
                .map(PendingNameServer::both)
                .collect();
            referral.candidates
        };
        self.prepare_candidates(&mut candidates, &stats);
        if candidates.is_empty() {
            debug!("DNS referral did not yield a usable name-server address");
            return Ok(false);
        }

        debug!(
            zone = ?referral.zone,
            candidate_count = candidates.len(),
            "following DNS referral"
        );
        self.record_delegation_success(state).await?;
        state.deferred_address_error = None;
        state.current_delegation_zone = referral.zone;
        state.zone_attempted = false;
        state.candidates = candidates;
        state.restart_from_root = true;
        state.reachable_dns_error = false;
        if let Some(stats) = stats {
            stats.increment_referrals_followed();
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{Arc, Mutex, atomic::AtomicUsize},
        time::Duration,
    };

    use dns::{ClassType, DomainName, Message, QClassType, QueryType, Question};
    use transport::{Transport, TransportError};

    use super::*;
    use crate::{ResolverConfig, protocol::Referral, resolver::AlgorithmSignals};

    #[derive(Clone, Copy)]
    struct NoIo;

    impl Transport for NoIo {
        fn exchange<'future>(
            &'future self,
            _server: SocketAddr,
            _query: &'future Message,
            _timeout: Duration,
        ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
            Box::pin(async move {
                panic!("trusted in-bailiwick glue should avoid address-resolution I/O")
            })
        }
    }

    fn name(labels: &[&str]) -> DomainName {
        DomainName::from_labels(
            labels
                .iter()
                .map(|label| label.as_bytes().to_vec())
                .collect(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn in_bailiwick_glue_seeds_the_current_resolution_and_enters_the_cache() {
        let name_server = name(&["ns", "example"]);
        let candidate = "192.0.2.53:53".parse().unwrap();
        let question = Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        let resolver = Resolver::new(NoIo, ResolverConfig::default());
        let mut state = ResolutionState {
            active_question: question.clone(),
            cname_answers: Vec::new(),
            cname_authorities: Vec::new(),
            proof_deadlines: Default::default(),
            cname_names: crate::name::NameSet::default(),
            current_delegation_zone: DomainName::root(),
            candidates: Vec::new(),
            pending_name_servers: Vec::new(),
            restart_from_root: false,
            zone_attempted: false,
            address_lookup: false,
            bootstraps: Vec::new(),
            recovery: Vec::new(),
            attempts: Arc::new(Mutex::new(
                crate::resolver::retry_budget::RetryBudget::default(),
            )),
            reachable_dns_error: false,
            cname_loop_seen: false,
            deferred_address_error: None,
            used_cached_delegation: false,
            algorithm_signals: Arc::new(AlgorithmSignals::default()),
            cache_allowed: true,
            validated_dnames_allowed: false,
        };
        let referral = Referral {
            zone: name(&["example"]),
            class: ClassType::IN,
            candidates: vec![candidate],
            candidate_ttls: vec![(candidate, Duration::from_secs(60))],
            trusted_glue: Vec::new(),
            name_servers: vec![name_server.clone()],
            ttl: Duration::from_secs(60),
        };

        assert!(
            resolver
                .follow_referral(
                    referral,
                    std::time::Instant::now(),
                    &[],
                    Arc::new(AtomicUsize::new(1)),
                    None,
                    &mut state,
                )
                .await
                .unwrap()
        );
        assert_eq!(state.candidates, [candidate]);
        assert_eq!(
            resolver.delegation_cache.get(&question).unwrap().candidates,
            [candidate]
        );
    }
    #[tokio::test]
    async fn unusable_or_nonprogressing_referrals_cannot_restore_retry_budgets() {
        let candidate = "192.0.2.53:53".parse().unwrap();
        let question = Question {
            qname: name(&["www", "a", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        let resolver = Resolver::new(NoIo, ResolverConfig::default());
        let mut budget = crate::resolver::retry_budget::RetryBudget::default();
        for _ in 0..3 {
            assert!(budget.reserve(&question, candidate, None, 3));
        }
        let mut state = ResolutionState {
            active_question: question.clone(),
            cname_answers: Vec::new(),
            cname_authorities: Vec::new(),
            proof_deadlines: Default::default(),
            cname_names: crate::name::NameSet::default(),
            current_delegation_zone: name(&["a", "example"]),
            candidates: Vec::new(),
            pending_name_servers: Vec::new(),
            restart_from_root: false,
            zone_attempted: false,
            address_lookup: false,
            bootstraps: Vec::new(),
            recovery: Vec::new(),
            attempts: Arc::new(Mutex::new(budget)),
            reachable_dns_error: false,
            cname_loop_seen: false,
            deferred_address_error: None,
            used_cached_delegation: false,
            algorithm_signals: Arc::new(AlgorithmSignals::default()),
            cache_allowed: true,
            validated_dnames_allowed: false,
        };
        for zone in [
            name(&["a", "example"]),
            name(&["b", "example"]),
            name(&["www", "a", "example"]),
        ] {
            let referral = Referral {
                zone,
                class: ClassType::IN,
                candidates: vec![],
                candidate_ttls: vec![],
                trusted_glue: vec![],
                name_servers: vec![],
                ttl: Duration::from_secs(60),
            };
            assert!(
                !resolver
                    .follow_referral(
                        referral,
                        std::time::Instant::now(),
                        &[],
                        Arc::new(AtomicUsize::new(32)),
                        None,
                        &mut state
                    )
                    .await
                    .unwrap()
            );
            assert!(
                !state
                    .attempts
                    .lock()
                    .unwrap()
                    .reserve(&question, candidate, None, 3)
            );
        }
    }
}

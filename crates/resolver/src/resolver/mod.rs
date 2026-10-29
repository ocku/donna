mod address;
mod backend;
mod cache;
mod coalescing;
mod delegation_recovery;
mod dnssec;
mod engine;
mod exchange;
mod failures;
mod referral;
mod response_handling;
mod retry_budget;
mod server_metrics;
mod state_machine;

use std::{
    sync::{Arc, Mutex, atomic::AtomicUsize},
    time::Instant,
};

use dns::{DnssecAlgorithmSignal, Edns, Message, Question};
use tracing::{debug, instrument, warn};
use transport::Transport;

use crate::{
    ResolutionCacheSource, ResolutionResult, ResolveError, ResolverConfig,
    cache::{
        bad::BadCache, delegation::DelegationCache, negative::NegativeCache,
        positive::PositiveCache,
    },
    response::validate_question,
    stats::StatsContext,
};

/// Resolves DNS questions iteratively with a caller-provided transport.
pub struct Resolver<T: Transport> {
    transport: Arc<T>,
    cache_engine: Option<crate::CacheEngineConfig>,
    engine_effects_retained: bool,
    config: ResolverConfig,
    positive_cache: PositiveCache,
    negative_cache: NegativeCache,
    bad_cache: BadCache,
    failure_cache: crate::cache::failure::FailureCache,
    cache_policy: Mutex<()>,
    delegation_cache: DelegationCache,
    in_flight: coalescing::InFlightTable,
    authenticated_zones: dnssec::AuthenticatedZoneCache,
    server_metrics: Mutex<server_metrics::ServerMetrics>,
    query_id_source: fn() -> u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct AlgorithmSignals {
    dau: Option<Vec<u8>>,
    dhu: Option<Vec<u8>>,
    n3u: Option<Vec<u8>>,
    checking_disabled: bool,
    recovery_grants: Vec<delegation_recovery::RecoveryGrant>,
}

impl AlgorithmSignals {
    pub(crate) fn from_edns(edns: &Edns) -> Self {
        let get = |signal| {
            edns.algorithm_signal(signal)
                .expect("the recursive server validates EDNS options first")
                .map(<[u8]>::to_vec)
        };
        Self {
            dau: get(DnssecAlgorithmSignal::Dau),
            dhu: get(DnssecAlgorithmSignal::Dhu),
            n3u: get(DnssecAlgorithmSignal::N3u),
            checking_disabled: false,
            recovery_grants: Vec::new(),
        }
    }

    pub(crate) fn apply_to(&self, edns: &mut Edns) {
        for (signal, algorithms) in [
            (DnssecAlgorithmSignal::Dau, &self.dau),
            (DnssecAlgorithmSignal::Dhu, &self.dhu),
            (DnssecAlgorithmSignal::N3u, &self.n3u),
        ] {
            if let Some(algorithms) = algorithms {
                // RFC 6975 receive validation allows unknown and reserved
                // values. Forward the advisory bytes without applying the
                // stricter policy for locally constructed algorithm lists.
                let code = signal.option_code();
                edns.options.retain(|option| option.code != code);
                edns.options.push(dns::EdnsOption {
                    code,
                    data: algorithms.clone(),
                });
                edns.dnssec_ok = true;
            }
        }
    }
}

impl<T: Transport> Resolver<T> {
    /// Creates a resolver that uses built-in root hints and default limits.
    pub fn with_defaults(transport: T) -> Self {
        Self::new(transport, ResolverConfig::default())
    }

    /// Creates a resolver that uses the specified transport and configuration.
    pub fn new(transport: T, config: ResolverConfig) -> Self {
        Self::new_with_id_source(transport, config, rand::random::<u16>)
    }

    fn new_with_id_source(
        transport: T,
        config: ResolverConfig,
        query_id_source: fn() -> u16,
    ) -> Self {
        let transport = Arc::new(transport);
        let positive_cache = PositiveCache::new(config.cache_capacity);
        let negative_cache = NegativeCache::new(config.cache_capacity);
        let bad_cache = BadCache::new(config.cache_capacity);
        let failure_cache = crate::cache::failure::FailureCache::new(config.cache_capacity);
        let delegation_cache = DelegationCache::new(config.cache_capacity);
        let in_flight = coalescing::InFlightTable::new(config.cache_capacity);
        let authenticated_zones = dnssec::AuthenticatedZoneCache::new(config.cache_capacity);
        let server_metrics = Mutex::new(server_metrics::ServerMetrics::new(config.cache_capacity));
        Self {
            transport,
            cache_engine: None,
            engine_effects_retained: true,
            config,
            positive_cache,
            negative_cache,
            bad_cache,
            failure_cache,
            cache_policy: Mutex::new(()),
            delegation_cache,
            in_flight,
            authenticated_zones,
            server_metrics,
            query_id_source,
        }
    }

    /// Resolves one single-message DNS question.
    ///
    /// The returned message contains the original question and its answer. The
    /// resolver follows referrals and CNAME chains, and it reuses eligible
    /// cached responses.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::UnsupportedQuestion`] for `QCLASS=ANY`, unknown
    /// classes, or zone-transfer operations. Returns another [`ResolveError`]
    /// if resolution can't produce a usable response within the configured
    /// transport and work limits.
    #[instrument(
        level = "debug",
        skip(self, question),
        fields(qname = ?question.qname, qtype = ?question.qtype, qclass = ?question.qclass)
    )]
    pub async fn resolve(&self, question: Question) -> Result<Message, ResolveError> {
        self.resolve_with_algorithm_signals(question, AlgorithmSignals::default(), false)
            .await
    }

    pub(crate) async fn resolve_with_algorithm_signals(
        &self,
        question: Question,
        algorithm_signals: AlgorithmSignals,
        checking_disabled: bool,
    ) -> Result<Message, ResolveError> {
        self.resolve_with_cache_check(question, algorithm_signals, checking_disabled, true)
            .await
    }

    pub(crate) async fn resolve_with_cache_check(
        &self,
        question: Question,
        algorithm_signals: AlgorithmSignals,
        checking_disabled: bool,
        check_cache: bool,
    ) -> Result<Message, ResolveError> {
        let started = Instant::now();
        if let Err(error) = validate_question(&question) {
            warn!(error = %error, "DNS resolution rejected unsupported question");
            debug!(elapsed = ?started.elapsed(), success = false, "DNS resolution completed");
            return Err(error);
        }
        // Positive answers are by far the most common cache hit. Keep this
        // before allocating shared work and statistics state.
        if (check_cache || self.uses_external_cache())
            && let Some(outcome) = self
                .cached_client_response_backend_with_policy(&question, !checking_disabled)
                .await?
        {
            debug!(elapsed = ?started.elapsed(), success = true,
                cache_source = ?outcome.cache_source, "DNS resolution completed");
            return Ok(outcome.response);
        }
        if !checking_disabled
            && !self.config.trust_anchors.is_empty()
            && self.bad_contains_backend(&question).await?
        {
            return Err(ResolveError::DnssecBogus(
                dns::DnssecValidationError::NoValidSignature,
            ));
        }

        let stats = Arc::new(StatsContext::new(self.config.max_concurrent_queries.max(1)));
        let validation_question = question.clone();
        let mut result = self
            .resolve_coalesced(
                question,
                Some(Arc::clone(&stats)),
                Arc::new(algorithm_signals),
                checking_disabled,
            )
            .await;
        if let Ok((outcome, history)) = &mut result {
            outcome.response.headers.ad = false;
            let mut final_validation = None;
            if !checking_disabled && !self.config.trust_anchors.is_empty() {
                let status = match self
                    .validate_dnssec_response_with_deadline(
                        &validation_question,
                        &mut outcome.response,
                        outcome.dname_deadline,
                    )
                    .await
                {
                    Ok(status) => status,
                    Err(error @ ResolveError::DnssecBogus(_)) => {
                        self.record_resolution_failure(
                            &validation_question,
                            checking_disabled,
                            &error,
                        )
                        .await?;
                        self.record_bad_backend(&validation_question).await?;
                        return Err(error);
                    }
                    Err(error) => {
                        self.record_resolution_failure(
                            &validation_question,
                            checking_disabled,
                            &error,
                        )
                        .await?;
                        return Err(error);
                    }
                };
                outcome.response.headers.ad = status.status == dns::DnssecSecurityStatus::Secure;
                self.cache_validated_response_with_sources_backend(
                    &outcome.response,
                    &validation_question,
                    &status,
                    &outcome.cached_dnames,
                )
                .await?;
                final_validation = Some(status);
            }
            if *history {
                self.clear_resolved_failure(&validation_question, checking_disabled)
                    .await?;
            }
            if let Some(status) = final_validation {
                status.recheck(&mut outcome.response)?;
            }
        }
        let cache_source = result
            .as_ref()
            .ok()
            .and_then(|(outcome, _)| outcome.cache_source);
        let snapshot = stats.snapshot(cache_source);
        log_resolution_summary(&snapshot, result.is_ok());
        result.map(|(outcome, _)| outcome.response)
    }

    /// Resolves one single-message DNS question and reports resolution statistics.
    ///
    /// This method has the same validation, cache, transport, and work-limit
    /// behavior as [`Self::resolve`]. Nested name-server hostname lookups are
    /// included in the returned per-resolution counters.
    ///
    /// # Errors
    ///
    /// Returns the same [`ResolveError`] values as [`Self::resolve`].
    #[instrument(
        level = "debug",
        skip(self, question),
        fields(qname = ?question.qname, qtype = ?question.qtype, qclass = ?question.qclass)
    )]
    pub async fn resolve_with_stats(
        &self,
        question: Question,
    ) -> Result<ResolutionResult, ResolveError> {
        let failure_question = question.clone();
        let stats = Arc::new(StatsContext::new(self.config.max_concurrent_queries.max(1)));
        let result = async {
            validate_question(&question).map_err(|error| {
                warn!(error = %error, "DNS resolution rejected unsupported question");
                error
            })?;
            if let Some(outcome) = self.cached_client_response_backend(&question).await? {
                return Ok(outcome);
            }
            if !self.config.trust_anchors.is_empty() && self.bad_contains_backend(&question).await?
            {
                return Err(ResolveError::DnssecBogus(
                    dns::DnssecValidationError::NoValidSignature,
                ));
            }
            let validation_question = question.clone();
            let (mut outcome, history) = self
                .resolve_coalesced(
                    question,
                    Some(Arc::clone(&stats)),
                    Arc::new(AlgorithmSignals::default()),
                    false,
                )
                .await?;
            outcome.response.headers.ad = false;
            let mut final_validation = None;
            if !self.config.trust_anchors.is_empty() {
                let status = match self
                    .validate_dnssec_response_with_deadline(
                        &validation_question,
                        &mut outcome.response,
                        outcome.dname_deadline,
                    )
                    .await
                {
                    Ok(status) => status,
                    Err(error @ ResolveError::DnssecBogus(_)) => {
                        self.record_resolution_failure(&validation_question, false, &error)
                            .await?;
                        self.record_bad_backend(&validation_question).await?;
                        return Err(error);
                    }
                    Err(error) => {
                        self.record_resolution_failure(&validation_question, false, &error)
                            .await?;
                        return Err(error);
                    }
                };
                outcome.response.headers.ad = status.status == dns::DnssecSecurityStatus::Secure;
                self.cache_validated_response_with_sources_backend(
                    &outcome.response,
                    &validation_question,
                    &status,
                    &outcome.cached_dnames,
                )
                .await?;
                final_validation = Some(status);
            }
            if history {
                self.clear_resolved_failure(&validation_question, false)
                    .await?;
            }
            if let Some(status) = final_validation {
                status.recheck(&mut outcome.response)?;
            }
            Ok(outcome)
        }
        .await;
        if let Err(error) = &result {
            self.record_resolution_failure(&failure_question, false, error)
                .await?;
        }
        let cache_source = result
            .as_ref()
            .ok()
            .and_then(|outcome| outcome.cache_source);
        let snapshot = stats.snapshot(cache_source);
        log_resolution_summary(&snapshot, result.is_ok());
        result.map(|outcome| ResolutionResult::new(outcome.response, snapshot))
    }

    async fn resolve_iteratively(
        &self,
        question: Question,
        stats: ResolutionStatsContext,
        algorithm_signals: Arc<AlgorithmSignals>,
        use_validated_dnames: bool,
    ) -> Result<ResolutionOutcome, ResolveError> {
        self.resolve_inner(
            question,
            Vec::new(),
            Arc::new(AtomicUsize::new(usize::from(self.config.max_steps))),
            stats,
            algorithm_signals,
            use_validated_dnames,
        )
        .await
    }
}

pub(super) type ResolutionStatsContext = Option<Arc<StatsContext>>;

pub(super) struct ResolutionOutcome {
    pub(super) response: Message,
    pub(super) cache_source: Option<ResolutionCacheSource>,
    /// Earliest absolute DNAME proof deadline from iterative assembly.
    pub(super) dname_deadline: Option<Instant>,
    cached_dnames: Vec<cache::dname::traversal::CachedDnameSource>,
}

fn log_resolution_summary(stats: &crate::ResolutionStats, success: bool) {
    debug!(
        success,
        elapsed = ?stats.elapsed(),
        udp_transmissions = stats.udp_transmissions(),
        tcp_transitions = stats.tcp_transitions(),
        tcp_completions = stats.tcp_completions(),
        response_rounds = stats.response_rounds(),
        referrals_followed = stats.referrals_followed(),
        name_server_lookups = stats.name_server_lookups(),
        name_server_family_races = stats.name_server_family_races(),
        canceled_name_server_family_lookups = stats.canceled_name_server_family_lookups(),
        edns_fallbacks = stats.edns_fallbacks(),
        timeouts = stats.timeouts(),
        transient_transport_failures = stats.transient_transport_failures(),
        server_latency_samples = stats.server_latency_samples(),
        server_timeout_penalties = stats.server_timeout_penalties(),
        server_io_penalties = stats.server_io_penalties(),
        server_metric_ordering_preferences = stats.server_metric_ordering_preferences(),
        server_metric_explorations = stats.server_metric_explorations(),
        coalesced_leaders = stats.coalesced_leaders(),
        coalesced_followers = stats.coalesced_followers(),
        coalesced_wait = ?stats.coalesced_wait(),
        cache_source = ?stats.final_cache_source(),
        "DNS resolution completed"
    );
}

#[cfg(test)]
mod tests;

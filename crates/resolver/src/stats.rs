use std::{
    sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use dns::Message;

/// Identifies the cache that supplied or accelerated a completed resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolutionCacheSource {
    /// The final response was served from the positive-answer cache.
    Positive,
    /// The final response was served from the negative-answer cache.
    Negative,
    /// Iterative resolution started from a cached delegation.
    Delegation,
}

/// Read-only measurements collected during one DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionStats {
    elapsed: Duration,
    udp_transmissions: usize,
    tcp_transitions: usize,
    tcp_completions: usize,
    response_rounds: usize,
    referrals_followed: usize,
    name_server_lookups: usize,
    name_server_family_races: usize,
    canceled_name_server_family_lookups: usize,
    edns_fallbacks: usize,
    timeouts: usize,
    transient_transport_failures: usize,
    server_latency_samples: usize,
    server_timeout_penalties: usize,
    server_io_penalties: usize,
    server_metric_ordering_preferences: usize,
    server_metric_explorations: usize,
    final_cache_source: Option<ResolutionCacheSource>,
    configured_race_width: usize,
    peak_race_width: usize,
    canceled_losers: usize,
    coalesced_leaders: usize,
    coalesced_followers: usize,
    coalesced_wait: Duration,
}

impl ResolutionStats {
    /// Returns the total wall-clock duration of the resolution.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Returns the number of UDP transmissions reserved.
    ///
    /// The resolver records this at the same successful reservation point used
    /// by its work and per-server attempt limits. This includes initial sends,
    /// EDNS fallbacks, and transitions into a transport identified as UDP.
    pub fn udp_transmissions(&self) -> usize {
        self.udp_transmissions
    }

    /// Returns the number of successful transitions into a transport identified as TCP.
    pub fn tcp_transitions(&self) -> usize {
        self.tcp_transitions
    }

    /// Returns the number of responses completed on a transitioned transport
    /// identified as TCP.
    pub fn tcp_completions(&self) -> usize {
        self.tcp_completions
    }

    /// Returns the number of candidate-server response rounds started.
    pub fn response_rounds(&self) -> usize {
        self.response_rounds
    }

    /// Returns the number of progressing referrals followed.
    pub fn referrals_followed(&self) -> usize {
        self.referrals_followed
    }

    /// Returns the number of A or AAAA name-server hostname lookups started.
    pub fn name_server_lookups(&self) -> usize {
        self.name_server_lookups
    }

    /// Returns the number of name-server address lookups in which the
    /// alternate address family was started after the family stagger.
    pub fn name_server_family_races(&self) -> usize {
        self.name_server_family_races
    }

    /// Returns the number of pending name-server family lookups canceled when
    /// the other family produced usable addresses first.
    pub fn canceled_name_server_family_lookups(&self) -> usize {
        self.canceled_name_server_family_lookups
    }

    /// Returns the number of classic-DNS retries made after EDNS rejection.
    pub fn edns_fallbacks(&self) -> usize {
        self.edns_fallbacks
    }

    /// Returns the number of transport timeout results observed.
    pub fn timeouts(&self) -> usize {
        self.timeouts
    }

    /// Returns the number of transient transport I/O failures observed.
    pub fn transient_transport_failures(&self) -> usize {
        self.transient_transport_failures
    }

    /// Returns the number of structurally valid, correlated response-latency
    /// samples admitted to the resolver's server metrics.
    pub fn server_latency_samples(&self) -> usize {
        self.server_latency_samples
    }

    /// Returns the number of temporary server-metric penalties caused by timeouts.
    pub fn server_timeout_penalties(&self) -> usize {
        self.server_timeout_penalties
    }

    /// Returns the number of temporary server-metric penalties caused by
    /// transient transport I/O failures.
    pub fn server_io_penalties(&self) -> usize {
        self.server_io_penalties
    }

    /// Returns the number of candidate rounds whose first server was selected
    /// using a learned latency sample or an exploration promotion.
    pub fn server_metric_ordering_preferences(&self) -> usize {
        self.server_metric_ordering_preferences
    }

    /// Returns the number of periodic unknown-or-stale server explorations selected.
    pub fn server_metric_explorations(&self) -> usize {
        self.server_metric_explorations
    }

    /// Returns the cache that supplied or accelerated the final response.
    ///
    /// `None` means the response was obtained iteratively from the configured
    /// root servers without starting from a cached delegation.
    pub fn final_cache_source(&self) -> Option<ResolutionCacheSource> {
        self.final_cache_source
    }

    /// Returns the configured maximum number of candidates in a response round.
    pub fn configured_race_width(&self) -> usize {
        self.configured_race_width
    }

    /// Returns the largest candidate batch started during this resolution.
    pub fn peak_race_width(&self) -> usize {
        self.peak_race_width
    }

    /// Returns the number of in-flight losing exchanges canceled after a winner.
    ///
    /// A loser is counted only when its still-pending future is dropped after
    /// another response causes the resolver to leave the current round.
    pub fn canceled_losers(&self) -> usize {
        self.canceled_losers
    }

    /// Returns the number of times this caller led an admitted coalesced resolution.
    ///
    /// A caller can become a leader after a previous leader fails, so this count
    /// is additive with [`Self::coalesced_followers`].
    pub fn coalesced_leaders(&self) -> usize {
        self.coalesced_leaders
    }

    /// Returns the number of in-flight resolutions this caller followed.
    ///
    /// Failed leaders wake followers to retry admission, so one caller can follow
    /// more than one leader before completing.
    pub fn coalesced_followers(&self) -> usize {
        self.coalesced_followers
    }

    /// Returns the total time this caller spent waiting for coalesced leaders.
    pub fn coalesced_wait(&self) -> Duration {
        self.coalesced_wait
    }
}

/// A successful DNS response together with its resolution measurements.
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    response: Message,
    stats: ResolutionStats,
}

impl ResolutionResult {
    pub(crate) fn new(response: Message, stats: ResolutionStats) -> Self {
        Self { response, stats }
    }

    /// Returns the resolved DNS response.
    pub fn response(&self) -> &Message {
        &self.response
    }

    /// Returns the measurements collected for this resolution.
    pub fn stats(&self) -> &ResolutionStats {
        &self.stats
    }

    /// Consumes the result and returns its response and measurements.
    pub fn into_parts(self) -> (Message, ResolutionStats) {
        (self.response, self.stats)
    }
}

pub(crate) struct StatsContext {
    started: Instant,
    udp_transmissions: AtomicUsize,
    tcp_transitions: AtomicUsize,
    tcp_completions: AtomicUsize,
    response_rounds: AtomicUsize,
    referrals_followed: AtomicUsize,
    name_server_lookups: AtomicUsize,
    name_server_family_races: AtomicUsize,
    canceled_name_server_family_lookups: AtomicUsize,
    edns_fallbacks: AtomicUsize,
    timeouts: AtomicUsize,
    transient_transport_failures: AtomicUsize,
    server_latency_samples: AtomicUsize,
    server_timeout_penalties: AtomicUsize,
    server_io_penalties: AtomicUsize,
    server_metric_ordering_preferences: AtomicUsize,
    server_metric_explorations: AtomicUsize,
    final_cache_source: AtomicU8,
    configured_race_width: usize,
    peak_race_width: AtomicUsize,
    canceled_losers: AtomicUsize,
    coalesced_leaders: AtomicUsize,
    coalesced_followers: AtomicUsize,
    coalesced_wait_nanos: AtomicU64,
}

impl StatsContext {
    const NO_CACHE_SOURCE: u8 = 0;
    const POSITIVE_CACHE: u8 = 1;
    const NEGATIVE_CACHE: u8 = 2;
    const DELEGATION_CACHE: u8 = 3;

    pub(crate) fn new(configured_race_width: usize) -> Self {
        Self {
            started: Instant::now(),
            udp_transmissions: AtomicUsize::new(0),
            tcp_transitions: AtomicUsize::new(0),
            tcp_completions: AtomicUsize::new(0),
            response_rounds: AtomicUsize::new(0),
            referrals_followed: AtomicUsize::new(0),
            name_server_lookups: AtomicUsize::new(0),
            name_server_family_races: AtomicUsize::new(0),
            canceled_name_server_family_lookups: AtomicUsize::new(0),
            edns_fallbacks: AtomicUsize::new(0),
            timeouts: AtomicUsize::new(0),
            transient_transport_failures: AtomicUsize::new(0),
            server_latency_samples: AtomicUsize::new(0),
            server_timeout_penalties: AtomicUsize::new(0),
            server_io_penalties: AtomicUsize::new(0),
            server_metric_ordering_preferences: AtomicUsize::new(0),
            server_metric_explorations: AtomicUsize::new(0),
            final_cache_source: AtomicU8::new(Self::NO_CACHE_SOURCE),
            configured_race_width,
            peak_race_width: AtomicUsize::new(0),
            canceled_losers: AtomicUsize::new(0),
            coalesced_leaders: AtomicUsize::new(0),
            coalesced_followers: AtomicUsize::new(0),
            coalesced_wait_nanos: AtomicU64::new(0),
        }
    }

    pub(crate) fn increment_udp_transmissions(&self) {
        self.udp_transmissions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_tcp_transitions(&self) {
        self.tcp_transitions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_tcp_completions(&self) {
        self.tcp_completions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_response_round(&self, width: usize) {
        self.response_rounds.fetch_add(1, Ordering::Relaxed);
        self.peak_race_width.fetch_max(width, Ordering::Relaxed);
    }

    pub(crate) fn increment_referrals_followed(&self) {
        self.referrals_followed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_name_server_lookups(&self) {
        self.name_server_lookups.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_name_server_family_races(&self) {
        self.name_server_family_races
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_canceled_name_server_family_lookups(&self) {
        self.canceled_name_server_family_lookups
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_edns_fallbacks(&self) {
        self.edns_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_timeouts(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_transient_transport_failures(&self) {
        self.transient_transport_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_server_latency_samples(&self) {
        self.server_latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_server_timeout_penalties(&self) {
        self.server_timeout_penalties
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_server_io_penalties(&self) {
        self.server_io_penalties.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_server_metric_ordering_preferences(&self) {
        self.server_metric_ordering_preferences
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_server_metric_explorations(&self) {
        self.server_metric_explorations
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add_canceled_losers(&self, count: usize) {
        self.canceled_losers.fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn increment_coalesced_leaders(&self) {
        self.coalesced_leaders.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_coalesced_followers(&self) {
        self.coalesced_followers.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(deprecated, reason = "Retain the atomic API supported by Rust 1.88.")]
    pub(crate) fn add_coalesced_wait(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let _ = self.coalesced_wait_nanos.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_add(nanos)),
        );
    }

    pub(crate) fn snapshot(
        &self,
        final_cache_source: Option<ResolutionCacheSource>,
    ) -> ResolutionStats {
        let cache_source = match final_cache_source {
            Some(ResolutionCacheSource::Positive) => Self::POSITIVE_CACHE,
            Some(ResolutionCacheSource::Negative) => Self::NEGATIVE_CACHE,
            Some(ResolutionCacheSource::Delegation) => Self::DELEGATION_CACHE,
            None => Self::NO_CACHE_SOURCE,
        };
        self.final_cache_source
            .store(cache_source, Ordering::Relaxed);
        ResolutionStats {
            elapsed: self.started.elapsed(),
            udp_transmissions: self.udp_transmissions.load(Ordering::Relaxed),
            tcp_transitions: self.tcp_transitions.load(Ordering::Relaxed),
            tcp_completions: self.tcp_completions.load(Ordering::Relaxed),
            response_rounds: self.response_rounds.load(Ordering::Relaxed),
            referrals_followed: self.referrals_followed.load(Ordering::Relaxed),
            name_server_lookups: self.name_server_lookups.load(Ordering::Relaxed),
            name_server_family_races: self.name_server_family_races.load(Ordering::Relaxed),
            canceled_name_server_family_lookups: self
                .canceled_name_server_family_lookups
                .load(Ordering::Relaxed),
            edns_fallbacks: self.edns_fallbacks.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            transient_transport_failures: self.transient_transport_failures.load(Ordering::Relaxed),
            server_latency_samples: self.server_latency_samples.load(Ordering::Relaxed),
            server_timeout_penalties: self.server_timeout_penalties.load(Ordering::Relaxed),
            server_io_penalties: self.server_io_penalties.load(Ordering::Relaxed),
            server_metric_ordering_preferences: self
                .server_metric_ordering_preferences
                .load(Ordering::Relaxed),
            server_metric_explorations: self.server_metric_explorations.load(Ordering::Relaxed),
            final_cache_source: match self.final_cache_source.load(Ordering::Relaxed) {
                Self::POSITIVE_CACHE => Some(ResolutionCacheSource::Positive),
                Self::NEGATIVE_CACHE => Some(ResolutionCacheSource::Negative),
                Self::DELEGATION_CACHE => Some(ResolutionCacheSource::Delegation),
                _ => None,
            },
            configured_race_width: self.configured_race_width,
            peak_race_width: self.peak_race_width.load(Ordering::Relaxed),
            canceled_losers: self.canceled_losers.load(Ordering::Relaxed),
            coalesced_leaders: self.coalesced_leaders.load(Ordering::Relaxed),
            coalesced_followers: self.coalesced_followers.load(Ordering::Relaxed),
            coalesced_wait: Duration::from_nanos(self.coalesced_wait_nanos.load(Ordering::Relaxed)),
        }
    }
}

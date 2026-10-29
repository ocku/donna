use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::{Duration, Instant},
};

use super::ResolutionStatsContext;

const DISABLED_CACHE_METRIC_CAPACITY: usize = 64;
const MAX_METRIC_CAPACITY: usize = 4_096;
const SAMPLE_MAX_AGE: Duration = Duration::from_secs(10 * 60);
const FAILURE_PENALTY_AGE: Duration = Duration::from_secs(30);
const MAX_SAMPLE: Duration = Duration::from_secs(30);
const EXPLORE_EVERY: u64 = 8;

#[derive(Debug)]
struct ServerMetric {
    ewma_nanos: Option<u64>,
    sampled_at: Option<Instant>,
    timeout_penalty_until: Option<Instant>,
    io_penalty_until: Option<Instant>,
    last_used: u64,
}

impl ServerMetric {
    fn new(last_used: u64) -> Self {
        Self {
            ewma_nanos: None,
            sampled_at: None,
            timeout_penalty_until: None,
            io_penalty_until: None,
            last_used,
        }
    }

    fn latency(&self, now: Instant) -> Option<u64> {
        self.sampled_at
            .filter(|sampled_at| now.duration_since(*sampled_at) <= SAMPLE_MAX_AGE)
            .and(self.ewma_nanos)
    }

    fn penalty(&self, now: Instant) -> u8 {
        u8::from(self.timeout_penalty_until.is_some_and(|until| until > now))
            + u8::from(self.io_penalty_until.is_some_and(|until| until > now))
    }

    fn is_stale(&self, now: Instant) -> bool {
        self.latency(now).is_none() && self.penalty(now) == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateRank {
    penalty: u8,
    exploration_priority: u8,
    unknown_ipv6: bool,
    latency_nanos: u64,
    tie_break: usize,
}

impl Ord for CandidateRank {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.penalty,
            self.exploration_priority,
            self.unknown_ipv6,
            self.latency_nanos,
            self.tie_break,
        )
            .cmp(&(
                other.penalty,
                other.exploration_priority,
                other.unknown_ipv6,
                other.latency_nanos,
                other.tie_break,
            ))
    }
}

impl PartialOrd for CandidateRank {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Bounded resolver-local responsiveness history.
///
/// Successful latency uses a deliberately simple EWMA: the previous estimate
/// receives weight 3/4 and the new sample receives weight 1/4. Samples are
/// capped before integer arithmetic, and all additions and multiplications
/// saturate. Timeout and transient-I/O penalties are independent, short-lived
/// signals and never alter the latency estimate.
pub(super) struct ServerMetrics {
    entries: HashMap<SocketAddr, ServerMetric>,
    capacity: usize,
    clock: u64,
    ordering_count: u64,
    exploration_cursor: usize,
}

impl ServerMetrics {
    pub(super) fn new(cache_capacity: usize) -> Self {
        let capacity = if cache_capacity == 0 {
            DISABLED_CACHE_METRIC_CAPACITY
        } else {
            cache_capacity.min(MAX_METRIC_CAPACITY)
        };
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
            clock: 0,
            ordering_count: 0,
            exploration_cursor: 0,
        }
    }

    pub(super) fn prepare_candidates(
        &mut self,
        candidates: &mut Vec<SocketAddr>,
        stats: &ResolutionStatsContext,
    ) {
        self.prepare_candidates_at(candidates, stats, Instant::now());
    }

    fn prepare_candidates_at(
        &mut self,
        candidates: &mut Vec<SocketAddr>,
        stats: &ResolutionStatsContext,
        now: Instant,
    ) {
        let mut seen = HashSet::with_capacity(candidates.len());
        candidates.retain(|candidate| seen.insert(*candidate));
        if candidates.len() < 2 {
            return;
        }

        self.clock = self.clock.saturating_add(1);
        self.ordering_count = self.ordering_count.saturating_add(1);
        self.entries.retain(|_, metric| !metric.is_stale(now));

        let rotation = (self.ordering_count as usize) % candidates.len();
        let mut ranks = HashMap::with_capacity(candidates.len());
        for (index, candidate) in candidates.iter().copied().enumerate() {
            let (penalty, latency_nanos) = match self.entries.get_mut(&candidate) {
                Some(metric) => {
                    metric.last_used = self.clock;
                    (metric.penalty(now), metric.latency(now).unwrap_or(u64::MAX))
                }
                None => (0, u64::MAX),
            };
            ranks.insert(
                candidate,
                CandidateRank {
                    penalty,
                    exploration_priority: 1,
                    // Prefer IPv4 while IPv6 reachability is unknown, preserving
                    // operation on hosts without an IPv6 route. A validated IPv6
                    // latency sample removes that preference so learned RTT and
                    // temporary failure penalties can select the better server.
                    unknown_ipv6: candidate.is_ipv6() && latency_nanos == u64::MAX,
                    latency_nanos,
                    tie_break: (index + rotation) % candidates.len(),
                },
            );
        }

        // Every eighth ordering promotes one unpenalized unknown/stale address.
        // The cursor rotates that opportunity across address families, so a
        // historical winner cannot permanently starve peers.
        if self.ordering_count.is_multiple_of(EXPLORE_EVERY) {
            let mut explorable = candidates
                .iter()
                .copied()
                .filter(|candidate| {
                    ranks[candidate].penalty == 0 && ranks[candidate].latency_nanos == u64::MAX
                })
                .collect::<Vec<_>>();
            if !explorable.is_empty() {
                explorable.sort_unstable();
                let selected = explorable[self.exploration_cursor % explorable.len()];
                self.exploration_cursor = self.exploration_cursor.saturating_add(1);
                let rank = ranks.get_mut(&selected).unwrap();
                rank.exploration_priority = 0;
                if let Some(stats) = stats {
                    stats.increment_server_metric_explorations();
                }
            }
        }

        // Lower ranks are better, while the state machine consumes with pop().
        // Sort worst-to-best so the exact first popped item is the best rank.
        candidates.sort_by(|left, right| ranks[right].cmp(&ranks[left]));
        let preferred = ranks[candidates.last().expect("candidate list is non-empty")];
        if (preferred.exploration_priority == 0 || preferred.latency_nanos != u64::MAX)
            && let Some(stats) = stats
        {
            stats.increment_server_metric_ordering_preferences();
        }
    }

    pub(super) fn record_success(
        &mut self,
        server: SocketAddr,
        elapsed: Duration,
        stats: &ResolutionStatsContext,
    ) {
        self.record_success_at(server, elapsed, stats, Instant::now());
    }

    fn record_success_at(
        &mut self,
        server: SocketAddr,
        elapsed: Duration,
        stats: &ResolutionStatsContext,
        now: Instant,
    ) {
        let clock = self.next_clock();
        self.make_room(server, now);
        let metric = self
            .entries
            .entry(server)
            .or_insert_with(|| ServerMetric::new(clock));
        let sample = duration_nanos(elapsed.min(MAX_SAMPLE));
        let previous = metric.latency(now);
        // EWMA(new) = 3/4 * old + 1/4 * sample. An expired estimate
        // is replaced rather than silently influencing a new observation.
        metric.ewma_nanos = Some(match previous {
            Some(old) => {
                old.saturating_mul(3)
                    .saturating_add(sample)
                    .saturating_add(2)
                    / 4
            }
            None => sample,
        });
        metric.sampled_at = Some(now);
        metric.timeout_penalty_until = None;
        metric.io_penalty_until = None;
        metric.last_used = clock;
        if let Some(stats) = stats {
            stats.increment_server_latency_samples();
        }
    }

    pub(super) fn record_timeout(&mut self, server: SocketAddr, stats: &ResolutionStatsContext) {
        self.record_penalty(server, stats, Instant::now(), true);
    }

    pub(super) fn record_io_failure(&mut self, server: SocketAddr, stats: &ResolutionStatsContext) {
        self.record_penalty(server, stats, Instant::now(), false);
    }

    fn record_penalty(
        &mut self,
        server: SocketAddr,
        stats: &ResolutionStatsContext,
        now: Instant,
        timeout: bool,
    ) {
        let clock = self.next_clock();
        self.make_room(server, now);
        let metric = self
            .entries
            .entry(server)
            .or_insert_with(|| ServerMetric::new(clock));
        let until = now + FAILURE_PENALTY_AGE;
        if timeout {
            metric.timeout_penalty_until = Some(until);
            if let Some(stats) = stats {
                stats.increment_server_timeout_penalties();
            }
        } else {
            metric.io_penalty_until = Some(until);
            if let Some(stats) = stats {
                stats.increment_server_io_penalties();
            }
        }
        metric.last_used = clock;
    }

    fn next_clock(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    fn make_room(&mut self, server: SocketAddr, now: Instant) {
        if self.entries.contains_key(&server) || self.entries.len() < self.capacity {
            return;
        }
        let victim = self
            .entries
            .iter()
            .filter(|(_, metric)| metric.is_stale(now))
            .min_by_key(|(_, metric)| metric.last_used)
            .or_else(|| {
                self.entries
                    .iter()
                    .min_by_key(|(_, metric)| metric.last_used)
            })
            .map(|(server, _)| *server);
        if let Some(victim) = victim {
            self.entries.remove(&victim);
        }
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(octet: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, octet], 53))
    }

    #[test]
    fn learned_latency_controls_the_exact_first_pop_and_keeps_deduplication() {
        let now = Instant::now();
        let slow = address(1);
        let fast = address(2);
        let mut metrics = ServerMetrics::new(16);
        metrics.record_success_at(slow, Duration::from_millis(80), &None, now);
        metrics.record_success_at(fast, Duration::from_millis(10), &None, now);
        let mut candidates = vec![fast, slow, fast];

        metrics.prepare_candidates_at(&mut candidates, &None, now);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates.pop(), Some(fast));
    }

    #[test]
    fn ipv4_is_preferred_while_ipv6_reachability_is_unknown() {
        let now = Instant::now();
        let ipv4 = address(1);
        let ipv6 = "[2001:db8::1]:53".parse().unwrap();
        let mut metrics = ServerMetrics::new(16);
        let mut candidates = vec![ipv4, ipv6];

        metrics.prepare_candidates_at(&mut candidates, &None, now);

        assert_eq!(candidates.pop(), Some(ipv4));
    }

    #[test]
    fn a_reachable_faster_ipv6_server_can_outrank_ipv4() {
        let now = Instant::now();
        let ipv4 = address(1);
        let ipv6 = "[2001:db8::1]:53".parse().unwrap();
        let mut metrics = ServerMetrics::new(16);
        metrics.record_success_at(ipv4, Duration::from_millis(100), &None, now);
        metrics.record_success_at(ipv6, Duration::from_millis(1), &None, now);
        let mut candidates = vec![ipv4, ipv6];

        metrics.prepare_candidates_at(&mut candidates, &None, now);

        assert_eq!(candidates.pop(), Some(ipv6));
    }

    #[test]
    fn penalties_are_temporary_and_latency_samples_age_out() {
        let now = Instant::now();
        let historically_fast = address(1);
        let slow = address(2);
        let mut metrics = ServerMetrics::new(16);
        metrics.record_success_at(historically_fast, Duration::from_millis(1), &None, now);
        metrics.record_success_at(slow, Duration::from_millis(20), &None, now);
        metrics.record_penalty(historically_fast, &None, now, true);

        let mut penalized = vec![slow, historically_fast];
        metrics.prepare_candidates_at(&mut penalized, &None, now);
        assert_eq!(penalized.pop(), Some(slow));

        let after_penalty = now + FAILURE_PENALTY_AGE + Duration::from_secs(1);
        let mut recovered = vec![slow, historically_fast];
        metrics.prepare_candidates_at(&mut recovered, &None, after_penalty);
        assert_eq!(recovered.pop(), Some(historically_fast));

        let after_expiry = now + SAMPLE_MAX_AGE + Duration::from_secs(1);
        let mut expired = vec![historically_fast, slow];
        metrics.prepare_candidates_at(&mut expired, &None, after_expiry);
        assert!(metrics.entries.is_empty());
    }

    #[test]
    fn capacity_is_bounded_and_stale_entries_are_safe_eviction_targets() {
        let now = Instant::now();
        let mut metrics = ServerMetrics::new(2);
        metrics.record_success_at(address(1), Duration::from_millis(1), &None, now);
        metrics.record_success_at(address(2), Duration::from_millis(2), &None, now);
        metrics.record_success_at(
            address(3),
            Duration::from_millis(3),
            &None,
            now + SAMPLE_MAX_AGE + Duration::from_secs(1),
        );

        assert_eq!(metrics.entries.len(), 2);
        assert!(metrics.entries.contains_key(&address(3)));
    }

    #[test]
    fn exploration_is_periodic_and_rotates_across_unknown_candidates() {
        let now = Instant::now();
        let winner = address(1);
        let unknown_one = address(2);
        let unknown_two = address(3);
        let mut metrics = ServerMetrics::new(16);
        metrics.record_success_at(winner, Duration::from_millis(1), &None, now);
        let mut explored = Vec::new();

        for _ in 0..16 {
            let mut candidates = vec![winner, unknown_one, unknown_two];
            metrics.prepare_candidates_at(&mut candidates, &None, now);
            let first = candidates.pop().unwrap();
            if first != winner {
                explored.push(first);
            }
        }

        assert_eq!(explored, [unknown_one, unknown_two]);
    }

    #[test]
    fn exploration_eventually_promotes_unknown_ipv6_past_known_ipv4() {
        let now = Instant::now();
        let ipv4 = address(1);
        let ipv6 = "[2001:db8::1]:53".parse().unwrap();
        let mut metrics = ServerMetrics::new(16);
        metrics.record_success_at(ipv4, Duration::ZERO, &None, now);
        let mut explored_ipv6 = false;

        for _ in 0..EXPLORE_EVERY * 2 {
            let mut candidates = vec![ipv4, ipv6];
            metrics.prepare_candidates_at(&mut candidates, &None, now);
            explored_ipv6 |= candidates.pop() == Some(ipv6);
        }

        assert!(explored_ipv6);
    }

    #[test]
    fn zero_cache_capacity_still_has_a_small_finite_metrics_bound() {
        let metrics = ServerMetrics::new(0);
        assert_eq!(metrics.capacity, DISABLED_CACHE_METRIC_CAPACITY);
        assert!(metrics.capacity < MAX_METRIC_CAPACITY);
    }
}

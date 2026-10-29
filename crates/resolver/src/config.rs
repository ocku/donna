use std::{net::SocketAddr, time::Duration};

use crate::root_hints;

/// Configures recursive resolution, caching, and resource limits.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Gets the bootstrap DNS server addresses.
    ///
    /// Use root-server addresses for full recursive resolution.
    pub root_servers: Vec<SocketAddr>,
    /// Gets the time limit for each UDP or TCP exchange.
    pub timeout: Duration,
    /// Gets the UDP payload size advertised in iterative EDNS(0) requests.
    ///
    /// Values below 512 are treated as 512 by responders. The RFC 6891
    /// recommended starting value is used by default.
    pub edns_udp_payload_size: u16,
    /// Gets the maximum number of DNS transmissions and timeout-processing steps.
    pub max_steps: u16,
    /// Gets the UDP attempts allowed for each server during one resolution.
    ///
    /// The count includes the first attempt and is clamped to 1..=3 (RFC 9520).
    /// Each other transport has an independent three-transmission ceiling.
    /// `max_steps` separately limits TCP
    /// completion of an attempted UDP query. A value of `0` allows one attempt.
    pub max_attempts_per_server: u8,
    /// Gets the candidate servers queried concurrently in each round.
    ///
    /// A value of `0` or `1` queries one server at a time. Larger values can
    /// reduce tail latency but send redundant queries. The first usable reply
    /// wins the round.
    pub max_concurrent_queries: usize,
    /// Gets the maximum lifetime of positive responses and delegations.
    pub max_ttl: Duration,
    /// Gets the maximum lifetime of negative responses.
    ///
    /// The effective value is also bounded by [`Self::max_ttl`], as required
    /// by RFC 2308's cache-lifetime guidance.
    pub max_negative_ttl: Duration,
    /// Gets the maximum entries retained in each built-in resolver cache.
    /// A custom CacheEngine owns its own nonzero retention/capacity policy.
    ///
    /// A value of `0` disables caching.
    pub cache_capacity: usize,
    /// Gets the locally assigned lifetime of repeated DNSSEC validation
    /// failures in the BAD cache, capped at five minutes by RFC 9520.
    pub max_bad_ttl: Duration,
    /// Gets the locally assigned lifetime of terminal resolution failures.
    ///
    /// The initial value is clamped to one second through five minutes. Each
    /// subsequent failure after expiry doubles it up to five minutes. History
    /// is retained for up to five minutes after suppression. A successful
    /// fresh resolution clears expired history; eviction also clears it.
    /// A concurrently recorded failure or a fast cached answer can leave
    /// history until expiry. Longer intervals delay recovery.
    /// RFC 9520 bounds the effective value to one second through five minutes,
    /// independently of received record TTLs. Zero-capacity caching remains an
    /// explicit opt-out. Keys include name, type, class and client CD mode.
    pub failure_ttl: Duration,
    /// Gets configured DNSKEY trust anchors used to enable DNSSEC validation.
    ///
    /// Each record must be a DNSKEY at the apex it anchors. An empty list
    /// leaves the resolver in non-validating mode.
    pub trust_anchors: Vec<dns::ResourceRecord>,
    /// Gets the maximum NSEC3 iteration count accepted during validation.
    pub max_nsec3_iterations: u16,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            root_servers: root_hints::SERVERS.to_vec(),
            timeout: Duration::from_secs(5),
            edns_udp_payload_size: dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE,
            max_steps: 32,
            max_attempts_per_server: 2,
            max_concurrent_queries: 1,
            max_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            max_negative_ttl: Duration::from_secs(3 * 60 * 60),
            cache_capacity: 4_096,
            max_bad_ttl: Duration::from_secs(30),
            failure_ttl: Duration::from_secs(1),
            trust_anchors: Vec::new(),
            max_nsec3_iterations: 150,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ResolverConfig;
    use std::time::Duration;

    #[test]
    fn default_configuration_has_root_hints_and_separate_negative_ttl_bound() {
        let config = ResolverConfig::default();
        assert_eq!(config.root_servers.len(), 13);
        assert!(config.root_servers.iter().all(|server| server.port() == 53));
        assert_eq!(
            config.edns_udp_payload_size,
            dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE
        );
        assert_eq!(config.max_negative_ttl, Duration::from_secs(3 * 60 * 60));
        assert!(config.max_negative_ttl <= config.max_ttl);
        assert!(config.trust_anchors.is_empty());
        assert_eq!(config.max_bad_ttl, Duration::from_secs(30));
        assert_eq!(config.max_nsec3_iterations, 150);
    }
}

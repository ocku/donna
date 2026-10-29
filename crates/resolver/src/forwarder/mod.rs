//! Forwarding policy and conservative complete-message caching.
use crate::{
    ResolverConfig,
    cache::failure::{FailureCache, FailureKind},
};
use dns::{Message, RCode, RData, RecordType};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use transport::Transport;

mod cache;
mod protocol;

use crate::protocol::MAX_TRANSMISSIONS_PER_SERVER;
use protocol::{correlate, validate};

#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod negative_cache_tests;
#[cfg(test)]
mod tests;

/// Resource and cache policy for a forwarding resolver.
#[derive(Clone, Debug)]
pub struct ForwarderConfig {
    /// Maximum cached messages and failure entries; zero disables caching.
    pub cache_capacity: usize,
    /// Maximum lifetime of any retained response.
    pub max_ttl: Duration,
    /// Additional lifetime bound for SOA-backed negative responses.
    pub max_negative_ttl: Duration,
    /// Deadline for an individual upstream exchange.
    pub timeout: Duration,
    /// Attempts per upstream, clamped to one through three.
    pub max_attempts_per_server: u8,
    /// Initial terminal-failure suppression, bounded by RFC 9520.
    pub failure_ttl: Duration,
}

impl Default for ForwarderConfig {
    fn default() -> Self {
        Self::from(&ResolverConfig::default())
    }
}

impl From<&ResolverConfig> for ForwarderConfig {
    fn from(config: &ResolverConfig) -> Self {
        Self {
            cache_capacity: config.cache_capacity,
            max_ttl: config.max_ttl,
            max_negative_ttl: config.max_negative_ttl,
            timeout: config.timeout,
            max_attempts_per_server: config.max_attempts_per_server,
            failure_ttl: config.failure_ttl,
        }
    }
}

struct Cached {
    message: Message,
    inserted: Instant,
    lifetime: Duration,
}

/// A forwarding resolver using ordered, explicitly configured recursive peers.
///
/// Upstream DNSSEC judgments are trusted. This handler does not perform local
/// DNSSEC validation. Complete-message caching preserves CD, DO, AD, and EDNS
/// request identity; option-bearing requests bypass the message cache.
pub struct Forwarder<T: Transport> {
    upstreams: Vec<(SocketAddr, T)>,
    cache: Mutex<HashMap<Vec<u8>, Cached>>,
    failures: FailureCache,
    failure_ttl: Duration,
    capacity: usize,
    max_ttl: u64,
    max_negative_ttl: u64,
    timeout: Duration,
    attempts: u8,
}

impl<T: Transport> Forwarder<T> {
    /// Creates a forwarding resolver with ordered upstreams and bounded caches.
    ///
    /// An empty upstream list returns SERVFAIL. Attempts are clamped to the
    /// RFC 9520 per-server limit. A zero cache capacity disables both response
    /// caching and terminal-failure suppression.
    pub fn new(upstreams: Vec<(SocketAddr, T)>, config: ForwarderConfig) -> Self {
        Self {
            upstreams,
            cache: Mutex::new(HashMap::new()),
            failures: FailureCache::new(config.cache_capacity),
            capacity: config.cache_capacity,
            max_ttl: config.max_ttl.as_secs(),
            max_negative_ttl: config.max_negative_ttl.as_secs(),
            timeout: config.timeout,
            attempts: config
                .max_attempts_per_server
                .clamp(1, MAX_TRANSMISSIONS_PER_SERVER),
            failure_ttl: config.failure_ttl,
        }
    }

    /// Immediately returns a protocol rejection, cached answer, or suppressed
    /// failure. Returns `None` when an upstream exchange is needed.
    pub fn try_answer_cached(&self, request: &Message) -> Option<Message> {
        if let Some(response) = validate(request) {
            return Some(response);
        }
        if self
            .failures
            .get(&request.questions[0], request.headers.cd)
            .is_some()
        {
            return Some(request.error_response(RCode::ServerFailure, true));
        }
        self.cached(request)
    }

    /// Answers a query through configured recursive peers, with failover,
    /// TTL-bounded response caching, and RFC 9520 terminal-failure suppression.
    pub async fn answer_message(&self, request: &Message) -> Message {
        if let Some(response) = self.try_answer_cached(request) {
            return response;
        }
        let mut outbound = request.clone();
        outbound.headers.rd = true;
        // Padding is hop-specific; downstream and upstream encryption differ.
        for r in &mut outbound.additionals {
            if let RData::OPT(options) = &mut r.rdata {
                options.retain(|o| o.code != dns::EDNS_PADDING_OPTION_CODE);
            }
        }
        for (address, transport) in &self.upstreams {
            for _ in 0..self.attempts {
                match transport.exchange(*address, &outbound, self.timeout).await {
                    Ok(mut response)
                        if ![RCode::ServerFailure, RCode::Refused]
                            .into_iter()
                            .any(|code| response.extended_rcode() == u16::from(u8::from(code))) =>
                    {
                        correlate(&mut response, request);
                        self.failures
                            .clear_expired(&request.questions[0], request.headers.cd);
                        self.remember(request, &response);
                        return response;
                    }
                    Ok(_) => break,
                    Err(error) => tracing::debug!(%address,%error,"forwarding exchange failed"),
                }
            }
        }
        self.failures.insert(
            &request.questions[0],
            request.headers.cd,
            FailureKind::Server,
            self.failure_ttl,
        );
        request.error_response(RCode::ServerFailure, true)
    }
}

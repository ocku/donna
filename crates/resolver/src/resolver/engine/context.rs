use super::super::{Resolver, coalescing, dnssec, server_metrics};
use std::sync::{Arc, Mutex};
use transport::Transport;
impl<T: Transport> Resolver<T> {
    /// Selects an application-owned per-entry cache algorithm. No native answer,
    /// delegation, validation-key or failure store is constructed in this mode.
    /// The configured engine owns admission/retention/eviction; core retains DNS
    /// coherence, sealing and lifetime checks. Zero capacity skips engine I/O.
    pub fn with_cache_engine(
        transport: T,
        config: crate::ResolverConfig,
        engine: crate::CacheEngineConfig,
    ) -> Self {
        let mut r = Self::engine_shell(Arc::new(transport), config, rand::random::<u16>, 0);
        r.authenticated_zones =
            dnssec::AuthenticatedZoneCache::for_engine_coordination(r.config.cache_capacity);
        r.in_flight = coalescing::InFlightTable::new(r.config.cache_capacity);
        r.server_metrics = Mutex::new(server_metrics::ServerMetrics::new(r.config.cache_capacity));
        r.cache_engine = Some(engine);
        r
    }
    fn engine_shell(
        transport: Arc<T>,
        config: crate::ResolverConfig,
        query_id_source: fn() -> u16,
        capacity: usize,
    ) -> Self {
        Self {
            transport,
            cache_engine: None,
            engine_effects_retained: true,
            config,
            positive_cache: crate::cache::positive::PositiveCache::for_engine(capacity),
            negative_cache: crate::cache::negative::NegativeCache::for_engine(capacity),
            delegation_cache: crate::cache::delegation::DelegationCache::for_engine(capacity),
            bad_cache: crate::cache::bad::BadCache::for_engine(capacity),
            failure_cache: crate::cache::failure::FailureCache::for_engine(capacity),
            authenticated_zones: dnssec::AuthenticatedZoneCache::for_engine(capacity),
            cache_policy: Mutex::new(()),
            in_flight: coalescing::InFlightTable::new(0),
            server_metrics: Mutex::new(server_metrics::ServerMetrics::new(0)),
            query_id_source,
        }
    }
    pub(super) fn engine_view(&self) -> Self {
        Self::engine_shell(
            Arc::clone(&self.transport),
            self.config.clone(),
            self.query_id_source,
            usize::MAX,
        )
    }
    pub(in crate::resolver) fn uses_external_cache(&self) -> bool {
        self.cache_engine.is_some()
    }
}

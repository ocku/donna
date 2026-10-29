use super::{
    super::Resolver,
    key_cache::{AuthenticatedLifetime, CachedZone, ValidationTime, ZoneKey},
};
use crate::ResolveError;
use dns::AuthenticatedDnskeySet;
use std::sync::Arc;
use transport::Transport;

impl<T: Transport> Resolver<T> {
    pub(super) async fn cached_authenticated_zone_backend(
        &self,
        key: &ZoneKey,
        time: ValidationTime,
    ) -> Result<Option<CachedZone>, ResolveError> {
        if !self.uses_external_cache() || self.config.cache_capacity == 0 {
            return Ok(self.authenticated_zones.get(key, time));
        }
        let (selected, context) = self
            .cache_transaction_with_context_for(
                &[super::super::engine::zone(&key.zone, key.class)],
                |context| Ok(context.authenticated_zones.get(key, time)),
            )
            .await?;
        if selected.is_none() {
            return Ok(None);
        }
        // A slow commit may outlast the authenticated chain or signature.
        // Check both the wall and monotonic guards again before using it.
        Ok(context
            .expect("external transaction returns its context")
            .authenticated_zones
            .get(key, ValidationTime::now()))
    }
    pub(super) async fn insert_authenticated_zone_backend(
        &self,
        key: ZoneKey,
        keys: Arc<AuthenticatedDnskeySet>,
        lifetime: AuthenticatedLifetime,
    ) -> Result<(), ResolveError> {
        self.cache_transaction_for(
            &[super::super::engine::zone(&key.zone, key.class)],
            |context| {
                context.authenticated_zones.insert_bounded(
                    key.clone(),
                    Arc::clone(&keys),
                    lifetime,
                    context.config.max_ttl,
                );
                Ok(())
            },
        )
        .await
    }
    pub(super) async fn allow_authenticated_refresh_backend(
        &self,
        key: &ZoneKey,
        used: &Arc<AuthenticatedDnskeySet>,
        time: ValidationTime,
    ) -> Result<bool, ResolveError> {
        if !self.uses_external_cache() || self.config.cache_capacity == 0 {
            return Ok(self.authenticated_zones.allow_refresh(key, used, time));
        }
        let (granted, context) = self
            .cache_transaction_with_context_for(
                &[super::super::engine::zone(&key.zone, key.class)],
                |c| Ok(c.authenticated_zones.allow_refresh(key, used, time)),
            )
            .await?;
        let context = context.expect("external cache committed context");
        let current = context.authenticated_zones.get(key, ValidationTime::now());
        if current.is_none_or(|current| !Arc::ptr_eq(&current.keys, used)) {
            // The failing cached key was evicted/replaced/expired while awaiting.
            // Permit a genuine fresh chain acquisition, never reuse that old Arc.
            return Ok(true);
        }
        // Exact sealed puts matching the retained state include our own refresh
        // marker. Do not replay allow_refresh or claim a discarded write.
        Ok((granted && context.engine_effects_retained)
            || !context
                .authenticated_zones
                .refresh_pending(key, used, ValidationTime::now()))
    }
}

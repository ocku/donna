//! Refresh ownership is a retained token, never merely a staged return value.
use super::{ClassType, DomainName, ResolveError, Resolver};
use transport::Transport;
impl<T: Transport> Resolver<T> {
    pub(super) async fn claim_delegation_refresh_backend(
        &self,
        zone: &DomainName,
        class: ClassType,
        cd: bool,
    ) -> Result<Option<u64>, ResolveError> {
        let (token, context) = self
            .cache_transaction_with_context_for(&[super::super::engine::zone(zone, class)], |c| {
                Ok(c.delegation_cache
                    .claim_refresh(zone, class, cd, c.config.failure_ttl))
            })
            .await?;
        Ok(token.filter(|token| {
            context
                .as_ref()
                .is_none_or(|c| c.delegation_cache.owns_refresh(zone, class, cd, *token))
        }))
    }
    pub(super) async fn start_delegation_refresh_backend(
        &self,
        zone: &DomainName,
        class: ClassType,
        cd: bool,
        token: u64,
    ) -> Result<bool, ResolveError> {
        let (started, context) = self
            .cache_transaction_with_context_for(&[super::super::engine::zone(zone, class)], |c| {
                Ok(c.delegation_cache
                    .start_refresh(zone, class, cd, token, c.config.failure_ttl))
            })
            .await?;
        Ok(started
            && context
                .as_ref()
                .is_none_or(|c| c.delegation_cache.owns_refresh(zone, class, cd, token)))
    }
}

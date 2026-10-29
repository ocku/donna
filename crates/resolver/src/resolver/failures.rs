//! Failure cache transactions finish before a failed leader releases followers.
use super::Resolver;
use crate::{ResolveError, cache::failure::FailureKind};
use dns::Question;
use transport::Transport;

impl<T: Transport> Resolver<T> {
    pub(super) async fn clear_resolved_failure(
        &self,
        question: &Question,
        checking_disabled: bool,
    ) -> Result<(), ResolveError> {
        self.cache_transaction_for(std::slice::from_ref(question), |context| {
            context
                .failure_cache
                .clear_expired(question, checking_disabled);
            Ok(())
        })
        .await
    }

    pub(super) async fn cached_resolution_failure(
        &self,
        question: &Question,
        checking_disabled: bool,
    ) -> Result<(Option<ResolveError>, bool), ResolveError> {
        self.cache_select_for(std::slice::from_ref(question), |context| {
            let (error, history) = context.failure_cache.lookup(question, checking_disabled);
            Ok((error.map(FailureKind::error), history))
        })
        .await
    }

    pub(super) async fn name_server_failure_cached(
        &self,
        question: &Question,
        checking_disabled: bool,
    ) -> Result<bool, ResolveError> {
        self.cache_select_for(std::slice::from_ref(question), |context| {
            Ok(context
                .failure_cache
                .get(question, checking_disabled)
                .is_some())
        })
        .await
    }

    pub(super) async fn check_name_server_target_failure(
        &self,
        original: &Question,
        state: &mut super::state_machine::ResolutionState<'_>,
    ) -> Result<(), ResolveError> {
        if !state.address_lookup || state.cache_allowed {
            return Ok(());
        }
        let cd = state.algorithm_signals.checking_disabled;
        let active = state.active_question.clone();
        if self
            .cache_select_for(&[original.clone(), active.clone()], |context| {
                Ok(context.failure_cache.get(original, cd).is_some()
                    || context.failure_cache.get(&active, cd).is_some())
            })
            .await?
        {
            return Err(ResolveError::CachedNameServerFailure);
        }
        Ok(())
    }

    pub(super) async fn record_resolution_failure(
        &self,
        question: &Question,
        checking_disabled: bool,
        error: &ResolveError,
    ) -> Result<(), ResolveError> {
        let Some(kind) = FailureKind::from_error(error) else {
            return Ok(());
        };
        self.cache_transaction_for(std::slice::from_ref(question), |context| {
            context.failure_cache.insert(
                question,
                checking_disabled,
                kind,
                context.config.failure_ttl,
            );
            Ok(())
        })
        .await
    }
}

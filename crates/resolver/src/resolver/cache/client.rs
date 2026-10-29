use crate::{ResolveError, resolver::Resolver, response::validate_question};
use dns::{Message, Question};
use transport::Transport;

impl<T: Transport> Resolver<T> {
    /// Uses the ordinary client cache boundary, including question validation,
    /// coherence locking, signature expiry, alias limits, and AD policy.
    pub(crate) fn try_resolve_cached(
        &self,
        question: &Question,
    ) -> Result<Option<Message>, ResolveError> {
        validate_question(question)?;
        if self.uses_external_cache() {
            return Ok(None);
        }
        Ok(self
            .cached_client_response(question)?
            .map(|outcome| outcome.response))
    }

    pub(crate) fn try_resolve_cached_with_policy(
        &self,
        question: &Question,
        allow_dnames: bool,
    ) -> Result<Option<Message>, ResolveError> {
        if allow_dnames {
            return self.try_resolve_cached(question);
        }
        validate_question(question)?;
        if self.uses_external_cache() {
            return Ok(None);
        }
        Ok(self
            .cached_client_response_with_policy(question, allow_dnames)?
            .map(|outcome| outcome.response))
    }

    pub(crate) fn try_resolve_cached_udp(
        &self,
        request: &Message,
        maximum: usize,
    ) -> Result<Option<transport::ImmediateUdpResponse>, ResolveError> {
        validate_question(&request.questions[0])?;
        if self.uses_external_cache() {
            return Ok(None);
        }
        self.cached_client_response_udp(request, maximum)
    }
}

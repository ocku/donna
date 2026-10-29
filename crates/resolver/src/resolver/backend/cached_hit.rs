//! Guard externally reconstructed cache responses with message-level signatures.
use dns::{RData, RecordType};

use super::super::ResolutionOutcome;

pub(super) fn safe(outcome: &ResolutionOutcome) -> bool {
    outcome
        .response
        .answers
        .iter()
        .chain(&outcome.response.authorities)
        .chain(&outcome.response.additionals)
        .all(|record| {
            record.rtype != RecordType::TSIG
                && !matches!(&record.rdata, RData::SIG(signature) if signature.is_sig0())
        })
}

impl<T: transport::Transport> super::super::Resolver<T> {
    pub(in crate::resolver) async fn cached_client_response_backend(
        &self,
        question: &dns::Question,
    ) -> Result<Option<ResolutionOutcome>, crate::ResolveError> {
        self.cached_client_response_backend_with_policy(question, true)
            .await
    }
    pub(in crate::resolver) async fn cached_client_response_backend_with_policy(
        &self,
        question: &dns::Question,
        allow_dnames: bool,
    ) -> Result<Option<ResolutionOutcome>, crate::ResolveError> {
        if !self.uses_external_cache() || self.config.cache_capacity == 0 {
            return self.cached_client_response_with_policy(question, allow_dnames);
        }
        // Carry selection errors as data: they may depend on a cache entry
        // that expires while the engine is committing the selected entries.
        let (_, context) = self
            .cache_transaction_with_context_for(std::slice::from_ref(question), |context| {
                Ok(context.cached_client_response_with_policy(question, allow_dnames))
            })
            .await?;
        // Reconstruct from the committed readset after the async CAS.
        // Its entries retain absolute deadlines; a rendered zero TTL can still
        // represent a live entry for less than one second. This second local
        // selection does not change the already committed popularity counters.
        Ok(context
            .expect("external transaction returns its context")
            .cached_client_response_with_policy(question, allow_dnames)?
            .filter(safe))
    }
}

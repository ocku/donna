//! DNSSEC validation result and its absolute delivery bounds.
use super::{reply_bounds::ReplyBounds, response_ttls::ResponseTtls};
use crate::ResolveError;
use dns::{DnssecSecurityStatus, Message, Question, RData, RecordType};

/// Per-RRset evidence is produced only by the validator, never by upstream AD.
pub(in crate::resolver) struct ValidationOutcome {
    pub(in crate::resolver) status: DnssecSecurityStatus,
    pub(in crate::resolver) negative_keys: Option<crate::cache::negative::DenialKeys>,
    pub(in crate::resolver) secure_dnames: Vec<ValidatedDname>,
    pub(super) authority_keys: Option<Vec<super::authority::AuthorityKey>>,
    pub(super) bounds: ReplyBounds,
    pub(super) ttls: Option<ResponseTtls>,
    pub(super) dname_deadline: Option<std::time::Instant>,
}

pub(in crate::resolver) struct ValidatedDname {
    pub(in crate::resolver) owner: dns::DomainName,
    pub(in crate::resolver) class: dns::ClassType,
    pub(in crate::resolver) deadline: std::time::Instant,
}

impl ValidationOutcome {
    pub(super) fn indeterminate() -> Self {
        Self {
            status: DnssecSecurityStatus::Indeterminate,
            negative_keys: None,
            secure_dnames: Vec::new(),
            authority_keys: None,
            bounds: ReplyBounds::default(),
            ttls: None,
            dname_deadline: None,
        }
    }

    /// A conservative absolute cap for newly projected authenticated components.
    pub(in crate::resolver) fn cache_deadline(
        &self,
        response: &Message,
    ) -> Option<std::time::Instant> {
        let bound = self.bounds.cache_deadline()?;
        std::iter::once(bound)
            .chain(
                self.ttls
                    .as_ref()
                    .and_then(|ttls| ttls.cache_deadline(response)),
            )
            .chain(self.dname_deadline)
            .chain(self.secure_dnames.iter().map(|dname| dname.deadline))
            .min()
    }

    pub(in crate::resolver) fn recheck(&self, response: &mut Message) -> Result<(), ResolveError> {
        self.bounds.finish(response)?;
        if let Some(ttls) = &self.ttls {
            ttls.clamp(response, std::time::Instant::now())?;
        }
        if let Some(deadline) = self.dname_deadline {
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_secs()
                .min(u64::from(u32::MAX)) as u32;
            for record in &mut response.answers {
                if record.rtype == RecordType::DNAME
                    || matches!(&record.rdata, RData::RRSIG(sig) if sig.type_covered == u16::from(RecordType::DNAME))
                {
                    record.ttl = record.ttl.min(remaining);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
impl<T: transport::Transport> super::Resolver<T> {
    pub(super) async fn validate_dnssec_response(
        &self,
        question: &Question,
        response: &mut Message,
    ) -> Result<DnssecSecurityStatus, ResolveError> {
        Ok(self
            .validate_dnssec_response_with_dnames(question, response)
            .await?
            .status)
    }

    pub(super) async fn validate_dnssec_response_with_dnames(
        &self,
        question: &Question,
        response: &mut Message,
    ) -> Result<ValidationOutcome, ResolveError> {
        self.validate_dnssec_response_with_deadline(question, response, None)
            .await
    }
}

impl<T: transport::Transport> super::Resolver<T> {
    pub(in crate::resolver) async fn validate_dnssec_response_with_deadline(
        &self,
        question: &Question,
        response: &mut Message,
        dname_deadline: Option<std::time::Instant>,
    ) -> Result<ValidationOutcome, ResolveError> {
        // Only the iterative path can supply this bound. A zero TTL may be
        // a rounded live proof, but never restore a truly expired proof.
        super::response_ttls::restore_dname_placeholder(response, dname_deadline);
        let observed_at = std::time::Instant::now();
        let mut ttls = ResponseTtls::capture(response, observed_at);
        let mut cached_keys = None;
        let result = self
            .validate_dnssec_response_once(
                question,
                response,
                &mut cached_keys,
                None,
                observed_at,
                dname_deadline,
            )
            .await;
        if matches!(result, Err(ResolveError::DnssecBogus(_)))
            && let Some(keys) = cached_keys
            && let Ok(Some(refreshed)) = self.refresh_authenticated_zone(&keys).await
        {
            // Retry the same selected packet once; TTL clamping already done
            // in the first attempt can only make this retry more conservative.
            let mut outcome = self
                .validate_dnssec_response_once(
                    question,
                    response,
                    &mut None,
                    Some(&refreshed),
                    observed_at,
                    dname_deadline,
                )
                .await?;
            if let Some(keys) = &outcome.authority_keys {
                ttls.retain_authorities(response, |record| {
                    keys.iter().any(|key| key.retains(record))
                });
            }
            outcome.ttls = Some(ttls);
            outcome.dname_deadline = dname_deadline;
            outcome.recheck(response)?;
            return Ok(outcome);
        }
        let mut outcome = result?;
        if let Some(keys) = &outcome.authority_keys {
            ttls.retain_authorities(response, |record| {
                keys.iter().any(|key| key.retains(record))
            });
        }
        outcome.ttls = Some(ttls);
        outcome.dname_deadline = dname_deadline;
        outcome.recheck(response)?;
        Ok(outcome)
    }
}

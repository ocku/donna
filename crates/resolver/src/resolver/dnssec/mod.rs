#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

mod authority;
mod backend;
mod cached_negative;
mod cached_response;
mod chain;
mod denial;
mod dname;
mod key_cache;
mod outcome;
mod records;
mod reply_bounds;
mod response_ttls;
mod validation;
mod zone_context;

pub(super) use key_cache::AuthenticatedZoneCache;

#[cfg(test)]
mod tests;

use dns::{Message, Question};
use transport::Transport;

use crate::ResolveError;

use self::chain::RefreshedZone;
#[cfg(test)]
use records::unix_time;

use super::Resolver;
pub(super) use outcome::{ValidatedDname, ValidationOutcome};
use std::sync::Arc;

impl<T: Transport> Resolver<T> {
    async fn validate_dnssec_response_once(
        &self,
        question: &Question,
        response: &mut Message,
        cached_keys: &mut Option<Arc<dns::AuthenticatedDnskeySet>>,
        refreshed: Option<&RefreshedZone>,
        observed_at: std::time::Instant,
        dname_deadline: Option<std::time::Instant>,
    ) -> Result<ValidationOutcome, ResolveError> {
        if self.config.trust_anchors.is_empty() {
            return Ok(ValidationOutcome::indeterminate());
        }
        validation::ResponseValidator::new(
            self,
            question,
            response,
            cached_keys,
            refreshed,
            observed_at,
            dname_deadline,
        )?
        .validate()
        .await
    }
}

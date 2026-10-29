//! Retarget retained denial material using the current authenticated key context.
use super::{
    Resolver,
    key_cache::{ValidationTime, ZoneKey},
};
use dns::{AuthenticatedDnskeySet, Message, QClassType, Question, RecordType};
use std::{sync::Arc, time::Instant};
use transport::Transport;

pub(in crate::resolver) struct CachedDenialContext {
    key: ZoneKey,
    keys: Arc<AuthenticatedDnskeySet>,
    deadline: Instant,
    authorities: Vec<super::authority::AuthorityKey>,
}
impl CachedDenialContext {
    pub(in crate::resolver) fn project_authorities(&self, response: &mut Message) {
        response
            .authorities
            .retain(|record| self.authorities.iter().any(|key| key.retains(record)));
    }

    pub(in crate::resolver) fn deadline(&self) -> Instant {
        self.deadline
    }
}
impl<T: Transport> Resolver<T> {
    pub(in crate::resolver) fn seed_negative_validation_cache(
        &self,
        response: &Message,
        question: &Question,
        validation: &super::ValidationOutcome,
    ) {
        if !response.headers.ad {
            return;
        }
        let Some(keys) = &validation.negative_keys else {
            return;
        };
        let qname = super::records::terminal_name(question, &response.answers);
        let terminal = Question {
            qname,
            ..question.clone()
        };
        self.negative_cache
            .seed_name_error_keys(&terminal, keys.clone());
    }

    pub(in crate::resolver) fn validate_cached_name_error(
        &self,
        response: &Message,
        question: &Question,
        selected: &crate::cache::negative::SelectedNegative,
    ) -> Option<CachedDenialContext> {
        let QClassType::Class(class) = question.qclass else {
            return None;
        };
        let zone = super::records::closest_soa_owner(response, &question.qname, class)?;
        self.check_answer_zone(
            &question.qname,
            &zone,
            class,
            question.qtype == dns::QueryType::DS,
        )
        .ok()?;
        let key = self.zone_cache_key(&zone, class).ok()?;
        let now = ValidationTime::now();
        let cached = self.authenticated_zones.get(&key, now)?;
        let proof_keys = selected.memoized_denial_keys(&cached.keys);
        let soa =
            super::records::records_at_type(&response.authorities, &zone, RecordType::SOA, class);
        let signatures = super::records::signatures_covering(
            &response.authorities,
            &zone,
            RecordType::SOA,
            class,
        );
        let soa = super::records::validation_result(proof_keys.validate_rrset(
            &soa,
            &signatures,
            now.unix,
        ))
        .ok()?;
        let denial = self
            .validate_negative_denial(
                &proof_keys,
                &question.qname,
                question.qtype.value(),
                response,
                now.unix,
            )
            .ok()?;
        if denial.opt_out() || denial.kind() != dns::DnssecDenialKind::NameError {
            return None;
        }
        let mut authorities = vec![super::authority::AuthorityKey(zone, RecordType::SOA, class)];
        super::authority::retain_denial_keys(&mut authorities, response, &denial);
        let ttl = soa.authenticated_ttl().min(denial.authenticated_ttl());
        let deadline = cached.deadline.min(
            now.instant
                .checked_add(std::time::Duration::from_secs(u64::from(ttl)))?,
        );
        let context = CachedDenialContext {
            key,
            keys: cached.keys,
            deadline,
            authorities,
        };
        self.cached_denial_context_live(&context).then_some(context)
    }

    pub(in crate::resolver) fn cached_denial_context_live(
        &self,
        context: &CachedDenialContext,
    ) -> bool {
        let now = ValidationTime::now();
        context.deadline > now.instant
            && self
                .authenticated_zones
                .get(&context.key, now)
                .is_some_and(|current| {
                    Arc::ptr_eq(&current.keys, &context.keys) && current.deadline > now.instant
                })
    }
}

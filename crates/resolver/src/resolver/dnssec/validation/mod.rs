//! Packet validation coordinated through one response-local evidence context.
mod answer;
mod negative;

use std::{sync::Arc, time::Instant};

use dns::{
    ClassType, DnssecSecurityStatus, DnssecValidationError, DomainName, Message, QClassType,
    QueryType, Question, RData, RecordType, ResourceRecord,
};
use transport::Transport;

use super::{
    authority,
    chain::{ChainStatus, RefreshedZone},
    dname,
    key_cache::ValidationTime,
    outcome::{ValidatedDname, ValidationOutcome},
    records::{
        answer_rrsets, clamp_denial_ttl, clamp_rrset_ttl, closest_soa_owner, is_negative,
        signature_signer, signatures_covering, terminal_name, validation_result,
    },
    reply_bounds::{Bound, Target},
};
use crate::{ResolveError, resolver::Resolver};

pub(super) struct ResponseValidator<'resolver, 'response, T: Transport> {
    resolver: &'resolver Resolver<T>,
    question: &'response Question,
    response: &'response mut Message,
    cached_keys: &'response mut Option<Arc<dns::AuthenticatedDnskeySet>>,
    refreshed: Option<&'response RefreshedZone>,
    observed_at: Instant,
    dname_deadline: Option<Instant>,
    time: ValidationTime,
    class: ClassType,
    bindings: Vec<dname::Binding>,
    outcome: ValidationOutcome,
    authority_keys: Vec<authority::AuthorityKey>,
}

struct SecureZone {
    keys: Arc<dns::AuthenticatedDnskeySet>,
    deadline: Instant,
    validated_at: ValidationTime,
    ttl: u32,
}

impl<'resolver, 'response, T: Transport> ResponseValidator<'resolver, 'response, T> {
    pub(super) fn new(
        resolver: &'resolver Resolver<T>,
        question: &'response Question,
        response: &'response mut Message,
        cached_keys: &'response mut Option<Arc<dns::AuthenticatedDnskeySet>>,
        refreshed: Option<&'response RefreshedZone>,
        observed_at: Instant,
        dname_deadline: Option<Instant>,
    ) -> Result<Self, ResolveError> {
        let QClassType::Class(class) = question.qclass else {
            return Err(ResolveError::DnssecIndeterminate(
                DnssecValidationError::InvalidRrset,
            ));
        };
        Ok(Self {
            resolver,
            question,
            response,
            cached_keys,
            refreshed,
            observed_at,
            dname_deadline,
            time: ValidationTime::now(),
            class,
            bindings: Vec::new(),
            outcome: ValidationOutcome::indeterminate(),
            authority_keys: Vec::new(),
        })
    }

    pub(super) async fn validate(mut self) -> Result<ValidationOutcome, ResolveError> {
        self.outcome.status = DnssecSecurityStatus::Secure;
        let mut rrsets = answer_rrsets(&self.response.answers);
        self.bindings = dname::bindings(&self.response.answers)?;
        self.clamp_derived_aliases();
        // Synthesized CNAMEs inherit security from their DNAME RRset.
        rrsets.retain(|rrset| {
            rrset[0].rtype != RecordType::CNAME
                || !self.bindings.iter().any(|binding| {
                    binding.class == rrset[0].class && binding.cname_owner.eq_dns(&rrset[0].name)
                })
        });
        let negative = is_negative(self.response, self.question);
        let unauthenticated_signatures = self.unauthenticated_signatures(&rrsets, negative);
        if rrsets.is_empty() && !negative {
            self.outcome.status = DnssecSecurityStatus::Indeterminate;
            return Ok(self.outcome);
        }
        for rrset in rrsets {
            self.validate_answer(rrset).await?;
        }
        if negative {
            self.validate_negative().await?;
        }
        self.outcome.bounds.finish(self.response)?;
        if unauthenticated_signatures {
            self.outcome.status = DnssecSecurityStatus::Indeterminate;
            self.outcome.secure_dnames.clear();
            self.outcome.negative_keys = None;
        }
        self.outcome.authority_keys = (negative
            && self.outcome.status == DnssecSecurityStatus::Secure)
            .then_some(self.authority_keys);
        Ok(self.outcome)
    }

    fn clamp_derived_aliases(&mut self) {
        // An alias cannot outlive its source DNAME, including in insecure zones.
        for binding in &self.bindings {
            if let Some(ttl) = self
                .response
                .answers
                .iter()
                .filter(|record| {
                    record.rtype == RecordType::DNAME
                        && record.class == binding.class
                        && record.name.eq_dns(&binding.dname_owner)
                })
                .map(|record| record.ttl)
                .min()
            {
                clamp_rrset_ttl(
                    &mut self.response.answers,
                    &binding.cname_owner,
                    RecordType::CNAME,
                    binding.class,
                    ttl,
                );
            }
        }
    }

    fn unauthenticated_signatures(&self, rrsets: &[Vec<ResourceRecord>], negative: bool) -> bool {
        // RRSIG records are not signed RRsets. Explicit signature answers and
        // ANY signatures without covered data cannot inherit authenticated AD.
        (self.question.qtype == QueryType::RRSIG && !negative)
            || (self.question.qtype == QueryType::ANY
                && self.response.answers.iter().any(|record| {
                    let RData::RRSIG(signature) = &record.rdata else {
                        return false;
                    };
                    !rrsets.iter().any(|rrset| {
                        rrset[0].name.eq_dns(&record.name)
                            && rrset[0].class == record.class
                            && u16::from(rrset[0].rtype) == signature.type_covered
                    })
                }))
    }

    async fn authenticate(
        &mut self,
        zone: &DomainName,
    ) -> Result<Option<SecureZone>, ResolveError> {
        let chain = if let Some(refreshed) = self
            .refreshed
            .filter(|refreshed| refreshed.matches(zone, self.class))
        {
            refreshed.status()?
        } else {
            self.resolver
                .authenticate_zone_at(zone, self.class, self.time)
                .await?
        };
        match chain {
            ChainStatus::Insecure {
                deadline,
                valid_until,
            } => {
                self.outcome.status = DnssecSecurityStatus::Insecure;
                self.outcome.bounds.add(
                    Target::WholeReply,
                    Bound::chain(ValidationTime::now(), deadline, valid_until),
                );
                Ok(None)
            }
            ChainStatus::Secure {
                keys,
                deadline,
                cached,
                valid_until,
            } => {
                let ttl = deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs()
                    .min(u64::from(u32::MAX)) as u32;
                *self.cached_keys = cached.then(|| Arc::clone(&keys));
                let validated_at = ValidationTime::now();
                self.outcome.bounds.add(
                    Target::Validity,
                    Bound::chain(validated_at, deadline, valid_until),
                );
                let elapsed = validated_at.unix.wrapping_sub(valid_until);
                if elapsed != 0 && elapsed <= dns::SerialNumber::MAX_INCREMENT {
                    return Err(ResolveError::DnssecBogus(DnssecValidationError::Signature(
                        dns::RrsigVerificationError::BadTime,
                    )));
                }
                Ok(Some(SecureZone {
                    keys,
                    deadline,
                    validated_at,
                    ttl,
                }))
            }
        }
    }
}

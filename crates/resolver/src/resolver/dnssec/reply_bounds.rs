//! Carry absolute per-component bounds across awaited chain acquisitions.
use super::{
    key_cache::ValidationTime,
    records::{clamp_all_ttl, clamp_denial_ttl, clamp_rrset_ttl},
};
use crate::ResolveError;
use dns::{ClassType, DomainName, Message, RecordType};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(super) struct Bound {
    at: ValidationTime,
    deadline: Instant,
    signature_lifetime: u32,
}

impl Bound {
    pub(super) fn deadline(self) -> Instant {
        self.deadline
    }

    pub(super) fn cap_deadline(mut self, deadline: Option<Instant>) -> Self {
        if let Some(deadline) = deadline {
            self.deadline = self.deadline.min(deadline);
        }
        self
    }

    pub(super) fn chain(at: ValidationTime, deadline: Instant, expires: u32) -> Self {
        Self {
            at,
            deadline,
            signature_lifetime: expires.wrapping_sub(at.unix),
        }
    }

    #[cfg(test)]
    pub(super) fn records(
        at: ValidationTime,
        ttl: u32,
        expires: u32,
        chain_deadline: Instant,
    ) -> Self {
        Self::records_since(at, at.instant, ttl, expires, chain_deadline)
    }

    /// TTL is measured from when the response entered validation, not from
    /// a later DNSKEY/DS lookup.  Signature validity is still checked at `at`.
    pub(super) fn records_since(
        at: ValidationTime,
        observed_at: Instant,
        ttl: u32,
        expires: u32,
        chain_deadline: Instant,
    ) -> Self {
        let deadline = observed_at
            .checked_add(Duration::from_secs(u64::from(ttl)))
            .unwrap_or(observed_at)
            .min(chain_deadline);
        Self::chain(at, deadline, expires)
    }

    fn valid(self, now: ValidationTime) -> bool {
        self.signature_lifetime < (1_u32 << 31)
            && now.unix.wrapping_sub(self.at.unix) <= self.signature_lifetime
            && now
                .instant
                .saturating_duration_since(self.at.instant)
                .as_secs()
                <= u64::from(self.signature_lifetime)
    }
}

pub(super) enum Target {
    Validity,
    Answer(DomainName, RecordType, ClassType),
    Authority(DomainName, RecordType, ClassType),
    Denial,
    WholeReply,
}

#[derive(Default)]
pub(super) struct ReplyBounds(Vec<(Target, Bound)>);

impl ReplyBounds {
    pub(super) fn cache_deadline(&self) -> Option<Instant> {
        let now = ValidationTime::now();
        if self.0.iter().any(|(_, bound)| !bound.valid(now)) {
            return None;
        }
        self.0.iter().map(|(_, bound)| bound.deadline).min()
    }

    pub(super) fn add(&mut self, target: Target, bound: Bound) {
        self.0.push((target, bound));
    }

    pub(super) fn finish(&self, response: &mut Message) -> Result<(), ResolveError> {
        self.finish_at(response, ValidationTime::now())
    }

    fn finish_at(&self, response: &mut Message, now: ValidationTime) -> Result<(), ResolveError> {
        // Check every earlier signature before projecting any relative TTL.
        if self.0.iter().any(|(_, bound)| !bound.valid(now)) {
            return Err(ResolveError::DnssecBogus(
                dns::DnssecValidationError::Signature(dns::RrsigVerificationError::BadTime),
            ));
        }
        for (target, bound) in &self.0 {
            let ttl = bound
                .deadline
                .saturating_duration_since(now.instant)
                .as_secs()
                .min(u64::from(u32::MAX)) as u32;
            match target {
                Target::Validity => {}
                Target::Answer(owner, rtype, class) => {
                    clamp_rrset_ttl(&mut response.answers, owner, *rtype, *class, ttl)
                }
                Target::Authority(owner, rtype, class) => {
                    clamp_rrset_ttl(&mut response.authorities, owner, *rtype, *class, ttl)
                }
                Target::Denial => clamp_denial_ttl(&mut response.authorities, ttl),
                Target::WholeReply => clamp_all_ttl(response, ttl),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{RData, ResourceRecord};

    fn record(owner: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: DomainName::from_dotted(owner).unwrap(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl,
            rdata: RData::A([192, 0, 2, 1].into()),
        }
    }

    #[test]
    fn later_work_cannot_renew_earlier_components_or_merge_their_ttls() {
        let at = ValidationTime::now();
        let a = record("a.example.", 30);
        let b = record("b.example.", 90);
        let mut response = Message {
            answers: vec![a.clone(), b.clone()],
            ..Message::builder().build().unwrap()
        };
        let mut bounds = ReplyBounds::default();
        for (record, ttl) in [(&a, 30), (&b, 90)] {
            bounds.add(
                Target::Answer(record.name.clone(), record.rtype, record.class),
                Bound::records(
                    at,
                    ttl,
                    at.unix.wrapping_add(300),
                    at.instant + Duration::from_secs(300),
                ),
            );
        }
        bounds
            .finish_at(
                &mut response,
                ValidationTime {
                    instant: at.instant + Duration::from_secs(7),
                    unix: at.unix.wrapping_add(7),
                },
            )
            .unwrap();
        assert_eq!(response.answers[0].ttl, 23);
        assert_eq!(response.answers[1].ttl, 83);
    }

    #[test]
    fn expired_signature_fails_but_expired_ttl_can_project_to_zero() {
        let at = ValidationTime::now();
        for (signature_ttl, success) in [(2, false), (300, true)] {
            let record = record("a.example.", 30);
            let mut response = Message {
                answers: vec![record.clone()],
                ..Message::builder().build().unwrap()
            };
            let mut bounds = ReplyBounds::default();
            bounds.add(
                Target::Answer(record.name.clone(), record.rtype, record.class),
                Bound::records(
                    at,
                    1,
                    at.unix.wrapping_add(signature_ttl),
                    at.instant + Duration::from_secs(300),
                ),
            );
            let result = bounds.finish_at(
                &mut response,
                ValidationTime {
                    instant: at.instant + Duration::from_secs(3),
                    unix: at.unix.wrapping_add(3),
                },
            );
            assert_eq!(result.is_ok(), success);
            if success {
                assert_eq!(response.answers[0].ttl, 0);
            }
        }
    }
}

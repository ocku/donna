//! Original packet TTLs retained across asynchronous validation and cache I/O.
use crate::ResolveError;
use dns::{DnssecValidationError, Message, RecordType, ResourceRecord};
use smallvec::SmallVec;
use std::time::{Duration, Instant};

/// Restore only an internal placeholder for live DNAME proof components
/// rounded to zero during iterative assembly. The caller must cap the
/// validated DNAME RRset by the same absolute deadline before exposing it.
pub(super) fn restore_dname_placeholder(response: &mut Message, deadline: Option<Instant>) {
    if !deadline.is_some_and(|end| end > Instant::now()) {
        return;
    }
    let dnames: SmallVec<[_; 2]> = response
        .answers
        .iter()
        .filter(|record| record.rtype == RecordType::DNAME)
        .map(|record| (record.name.clone(), record.class))
        .collect();
    for record in &mut response.answers {
        if record.ttl == 0
            && (record.rtype == RecordType::DNAME
                || (matches!(&record.rdata, dns::RData::RRSIG(sig) if sig.type_covered == u16::from(RecordType::DNAME))
                    && dnames.iter().any(|(owner, class)| {
                        *class == record.class && owner.eq_dns(&record.name)
                    })))
        {
            record.ttl = 1;
        }
    }
}

pub(super) struct ResponseTtls {
    at: Instant,
    answers: SmallVec<[u32; 8]>,
    authorities: SmallVec<[u32; 8]>,
    additionals: SmallVec<[u32; 4]>,
}

impl ResponseTtls {
    pub(super) fn retain_authorities(
        &mut self,
        response: &mut Message,
        keep: impl Fn(&ResourceRecord) -> bool,
    ) {
        if response.authorities.len() != self.authorities.len() {
            return;
        }
        let mask: SmallVec<[bool; 8]> = response.authorities.iter().map(keep).collect();
        let mut index = 0;
        response.authorities.retain(|_| {
            let yes = mask[index];
            index += 1;
            yes
        });
        let mut index = 0;
        self.authorities.retain(|_| {
            let yes = mask[index];
            index += 1;
            yes
        });
    }

    pub(super) fn cache_deadline(&self, response: &Message) -> Option<Instant> {
        response
            .answers
            .iter()
            .zip(&self.answers)
            .chain(response.authorities.iter().zip(&self.authorities))
            .chain(response.additionals.iter().zip(&self.additionals))
            .filter(|(record, _)| !matches!(record.rtype, RecordType::OPT | RecordType::TSIG))
            .map(|(_, ttl)| {
                self.at
                    .checked_add(Duration::from_secs(u64::from(*ttl)))
                    .unwrap_or(self.at)
            })
            .min()
    }

    pub(super) fn capture(response: &Message, at: Instant) -> Self {
        Self {
            at,
            answers: response.answers.iter().map(|rr| rr.ttl).collect(),
            authorities: response.authorities.iter().map(|rr| rr.ttl).collect(),
            additionals: response.additionals.iter().map(|rr| rr.ttl).collect(),
        }
    }

    pub(super) fn clamp(&self, response: &mut Message, now: Instant) -> Result<(), ResolveError> {
        if response.answers.len() != self.answers.len()
            || response.authorities.len() != self.authorities.len()
            || response.additionals.len() != self.additionals.len()
        {
            return Err(ResolveError::DnssecIndeterminate(
                DnssecValidationError::InvalidRrset,
            ));
        }
        fn section(records: &mut [ResourceRecord], original: &[u32], at: Instant, now: Instant) {
            for (record, ttl) in records.iter_mut().zip(original) {
                if matches!(record.rtype, RecordType::OPT | RecordType::TSIG) {
                    continue;
                }
                let expires = at
                    .checked_add(Duration::from_secs(u64::from(*ttl)))
                    .unwrap_or(at);
                let remaining = expires
                    .saturating_duration_since(now)
                    .as_secs()
                    .min(u64::from(u32::MAX)) as u32;
                record.ttl = record.ttl.min(remaining);
            }
        }
        section(&mut response.answers, &self.answers, self.at, now);
        section(&mut response.authorities, &self.authorities, self.at, now);
        section(&mut response.additionals, &self.additionals, self.at, now);
        Ok(())
    }
}

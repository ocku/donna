//! Absolute lower bound for alias and denial material retained across awaits.
use dns::{DomainName, QClassType, QueryType, Question, RData, RecordType, ResourceRecord};
use std::time::{Duration, Instant};

/// One conservative deadline bounds retained records without renewing a proof.
/// Weak source provenance is additionally bounded by the resolution work budget.
#[derive(Default)]
pub(in crate::resolver) struct ProofDeadlines(
    Option<Instant>,
    Vec<super::super::cache::dname::traversal::CachedDnameSource>,
);

impl ProofDeadlines {
    pub(in crate::resolver) fn retain_cached_dname(
        &mut self,
        source: super::super::cache::dname::traversal::CachedDnameSource,
    ) {
        self.1.push(source);
    }
    pub(in crate::resolver) fn cached_dnames(
        &self,
    ) -> Vec<super::super::cache::dname::traversal::CachedDnameSource> {
        self.1.clone()
    }
    pub(in crate::resolver) fn deadline(&self) -> Option<Instant> {
        self.0
    }
    pub(in crate::resolver) fn observe(&mut self, records: &[ResourceRecord], at: Instant) {
        for record in records {
            // RFC 6672 permits a synthesized CNAME to have TTL zero even
            // while its authenticated DNAME remains cacheable. Its own TTL
            // stays zero; do not let it expire the independent DNAME proof.
            // Ordinary CNAMEs (including malformed or ambiguous synthesis)
            // continue to bound the retained response as before.
            if record.ttl == 0 && is_dname_alias(record, records) {
                continue;
            }
            let deadline = at
                .checked_add(Duration::from_secs(u64::from(record.ttl)))
                .unwrap_or(at);
            self.0 = Some(self.0.map_or(deadline, |previous| previous.min(deadline)));
        }
    }
    pub(in crate::resolver) fn clamp(&self, records: &mut [ResourceRecord], now: Instant) {
        let Some(deadline) = self.0 else { return };
        let remaining = deadline
            .saturating_duration_since(now)
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
        for record in records {
            record.ttl = record.ttl.min(remaining);
        }
    }

    /// Ordinary CNAME chains can coexist with independently cached terminal
    /// RRsets. Do not shorten the terminal's TTL to the alias deadline.
    pub(in crate::resolver) fn clamp_answers(&self, records: &mut [ResourceRecord], now: Instant) {
        if records.iter().any(|rr| rr.rtype == RecordType::DNAME) {
            self.clamp(records, now);
            return;
        }
        let Some(deadline) = self.0 else { return };
        let remaining = deadline
            .saturating_duration_since(now)
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
        for record in records {
            let is_alias = record.rtype == RecordType::CNAME
                || matches!(&record.rdata, RData::RRSIG(sig) if sig.type_covered == u16::from(RecordType::CNAME))
                || matches!(&record.rdata, RData::SIG(sig) if sig.type_covered == u16::from(RecordType::CNAME));
            if is_alias {
                record.ttl = record.ttl.min(remaining);
            }
        }
    }
}

fn is_dname_alias(record: &ResourceRecord, records: &[ResourceRecord]) -> bool {
    // Structural matching scans the packet. Bound work for hostile responses;
    // above this size we retain the existing conservative zero deadline.
    const MAX_ALIAS_SCAN: usize = 128;
    if records.len() > MAX_ALIAS_SCAN {
        return false;
    }
    if record.rtype != RecordType::CNAME || !matches!(record.rdata, RData::CNAME(_)) {
        return false;
    }
    let question = Question {
        qname: record.name.clone(),
        qtype: QueryType::A,
        qclass: QClassType::Class(record.class),
    };
    let Ok(Some((dname, _))) =
        crate::response::checked_substitution(records, &question, &DomainName::root())
    else {
        return false;
    };
    if dname
        .name
        .as_ref()
        .iter()
        .any(|label| label.as_slice() == b"*")
    {
        return false;
    }
    let covered = |owner: &DomainName, ty: RecordType, rr: &ResourceRecord| {
        rr.class == record.class
            && rr.name.eq_dns(owner)
            && rr.rtype == RecordType::RRSIG
            && matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == u16::from(ty))
    };
    records.iter().any(|rr| {
        covered(&dname.name, RecordType::DNAME, rr)
            && matches!(&rr.rdata, RData::RRSIG(sig) if usize::from(sig.labels) == dname.name.as_ref().len())
    }) && !records.iter().any(|rr| covered(&record.name, RecordType::CNAME, rr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{ClassType, DomainName, RData, RecordType};
    #[test]
    fn zero_ttl_synthesized_alias_does_not_expire_its_dname() {
        let at = Instant::now();
        let name = |s: &str| DomainName::from_dotted(s).unwrap();
        let dname = ResourceRecord {
            name: name("old.example"),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 20,
            rdata: RData::DNAME(name("new.example")),
        };
        let cname = ResourceRecord {
            name: name("www.old.example"),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::CNAME(name("www.new.example")),
        };
        let signature = ResourceRecord {
            name: dname.name.clone(),
            rtype: RecordType::RRSIG,
            class: ClassType::IN,
            ttl: 20,
            rdata: RData::RRSIG(dns::Rrsig {
                type_covered: u16::from(RecordType::DNAME),
                algorithm: 8,
                labels: 2,
                original_ttl: 20,
                signature_expiration: 100,
                signature_inception: 1,
                key_tag: 1,
                signer_name: name("example"),
                signature: vec![1],
            }),
        };
        let mut records = vec![dname.clone(), cname.clone(), signature.clone()];
        let mut deadlines = ProofDeadlines::default();
        deadlines.observe(&records, at);
        deadlines.clamp(&mut records, at + Duration::from_secs(3));
        assert_eq!(records[0].ttl, 17);
        assert_eq!(records[1].ttl, 0);

        // A zero-TTL CNAME unrelated to the DNAME must still bound the chain.
        let mut unrelated = cname;
        unrelated.rdata = RData::CNAME(name("else.example"));
        let mut deadlines = ProofDeadlines::default();
        deadlines.observe(&[dname.clone(), unrelated, signature], at);
        let mut selected = vec![dname];
        deadlines.clamp(&mut selected, at);
        assert_eq!(selected[0].ttl, 0);
    }

    #[test]
    fn unsigned_wildcard_and_ambiguous_aliases_keep_zero_deadline() {
        let at = Instant::now();
        let name = |s: &str| DomainName::from_dotted(s).unwrap();
        let dname = ResourceRecord {
            name: name("old.example"),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 20,
            rdata: RData::DNAME(name("new.example")),
        };
        let alias = ResourceRecord {
            name: name("www.old.example"),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::CNAME(name("www.new.example")),
        };
        assert!(!is_dname_alias(&alias, &[dname.clone(), alias.clone()]));
        let mut signature = ResourceRecord {
            name: dname.name.clone(),
            rtype: RecordType::RRSIG,
            class: ClassType::IN,
            ttl: 20,
            rdata: RData::RRSIG(dns::Rrsig {
                type_covered: 39,
                algorithm: 8,
                labels: 1,
                original_ttl: 20,
                signature_expiration: 100,
                signature_inception: 1,
                key_tag: 1,
                signer_name: name("example"),
                signature: vec![1],
            }),
        };
        assert!(!is_dname_alias(
            &alias,
            &[dname.clone(), alias.clone(), signature.clone()]
        ));
        if let RData::RRSIG(sig) = &mut signature.rdata {
            sig.labels = 2;
        }
        let mut conflicting = alias.clone();
        conflicting.rdata = RData::CNAME(name("other.example"));
        let records = vec![dname.clone(), alias.clone(), signature, conflicting];
        assert!(!is_dname_alias(&alias, &records));
        let mut deadlines = ProofDeadlines::default();
        deadlines.observe(&records, at);
        let mut selected = vec![dname];
        deadlines.clamp(&mut selected, at);
        assert_eq!(selected[0].ttl, 0);
    }
    #[test]
    fn delayed_hops_and_repeat_observations_do_not_renew_proof() {
        let at = Instant::now();
        let original = ResourceRecord {
            name: DomainName::from_dotted("old.example").unwrap(),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 10,
            rdata: RData::DNAME(DomainName::from_dotted("new.other").unwrap()),
        };
        let mut repeated = original.clone();
        repeated.ttl = 30;
        let mut deadlines = ProofDeadlines::default();
        deadlines.observe(std::slice::from_ref(&original), at);
        deadlines.observe(std::slice::from_ref(&repeated), at + Duration::from_secs(4));
        let mut returned = vec![repeated];
        deadlines.clamp(&mut returned, at + Duration::from_secs(7));
        assert_eq!(returned[0].ttl, 3);
        deadlines.clamp(&mut returned, at + Duration::from_secs(11));
        assert_eq!(returned[0].ttl, 0);
    }

    #[test]
    fn composing_a_later_cached_target_keeps_the_shorter_dname_deadline() {
        use dns::{Headers, Message, QClassType, QueryType, Question};
        let at = Instant::now();
        let name = |s: &str| DomainName::from_dotted(s).unwrap();
        let question = Question {
            qname: name("www.old.example"),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        let dname = ResourceRecord {
            name: name("old.example"),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 8,
            rdata: RData::DNAME(name("new.other")),
        };
        let signature = ResourceRecord {
            name: name("old.example"),
            rtype: RecordType::RRSIG,
            class: ClassType::IN,
            ttl: 8,
            rdata: RData::RRSIG(dns::Rrsig {
                type_covered: 39,
                algorithm: 8,
                labels: 2,
                original_ttl: 8,
                signature_expiration: 100,
                signature_inception: 1,
                key_tag: 1,
                signer_name: name("example"),
                signature: vec![1],
            }),
        };
        let cname = ResourceRecord {
            name: question.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 8,
            rdata: RData::CNAME(name("www.new.other")),
        };
        let cached_target = ResourceRecord {
            name: name("www.new.other"),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 50,
            rdata: RData::A(std::net::Ipv4Addr::LOCALHOST),
        };
        let mut deadlines = ProofDeadlines::default();
        deadlines.observe(&[dname.clone(), signature.clone(), cname.clone()], at);
        let cached = Message {
            headers: Headers {
                qr: true,
                ..Headers::default()
            },
            questions: vec![],
            answers: vec![cached_target],
            authorities: vec![],
            additionals: vec![],
        };
        let mut composed = crate::response::complete_cname_response(
            cached,
            &question,
            vec![dname, signature, cname],
            vec![],
        );
        deadlines.clamp(&mut composed.answers, at + Duration::from_secs(6));
        assert_eq!(
            composed
                .answers
                .iter()
                .map(|rr| rr.rtype)
                .collect::<Vec<_>>(),
            vec![
                RecordType::DNAME,
                RecordType::RRSIG,
                RecordType::CNAME,
                RecordType::A
            ]
        );
        assert!(composed.answers.iter().all(|rr| rr.ttl == 2));
    }
}

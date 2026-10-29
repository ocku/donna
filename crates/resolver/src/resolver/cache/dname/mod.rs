//! Authentication-bound DNAME cache entries and ancestor selection.

pub(in crate::resolver) mod traversal;

use dns::{DomainName, Message, QClassType, QueryType, Question, RCode, RData, RecordType};
use std::time::{Duration, Instant};
use transport::Transport;

use super::super::Resolver;

pub(in crate::resolver) struct CachedDname {
    pub(in crate::resolver) selection: crate::cache::positive::SelectedPositive,
    pub(in crate::resolver) question: Question,
    pub(in crate::resolver) target: Result<DomainName, dns::DomainNameError>,
}

impl<T: Transport> Resolver<T> {
    /// Project independently validated DNAME RRsets out of a completed answer.
    /// Derived CNAMEs are never cached as independent aliases.
    pub(in crate::resolver) fn cache_validated_dnames(
        &self,
        response: &Message,
        question: &Question,
        secure_dnames: &[super::super::dnssec::ValidatedDname],
        observed_at: Instant,
        sources: &[super::super::cache::dname::traversal::CachedDnameSource],
    ) {
        let QClassType::Class(class) = question.qclass else {
            return;
        };
        if self.config.trust_anchors.is_empty()
            || !response
                .answers
                .iter()
                .any(|rr| rr.rtype == RecordType::DNAME)
        {
            return;
        }
        for dname in connected_dnames(
            response,
            question,
            class,
            usize::from(self.config.max_steps).max(1),
        ) {
            let evidence = secure_dnames
                .iter()
                .find(|evidence| evidence.class == class && evidence.owner.eq_dns(&dname.name));
            if !response.headers.ad && evidence.is_none() {
                continue;
            }
            // Wildcard DNAME synthesis has unspecified behavior (RFC 6672
            // section 3.3). Do not use a wildcard-expanded RRset as a cached
            // ancestor, even when a signed response validated successfully.
            if dname
                .name
                .as_ref()
                .iter()
                .any(|label| label.as_slice() == b"*")
            {
                continue;
            }
            let signatures: Vec<_> = response
                .answers
                .iter()
                .filter(|rr| {
                    rr.name.eq_dns(&dname.name)
                        && rr.class == class
                        && rr.rtype == RecordType::RRSIG
                        && matches!(&rr.rdata, RData::RRSIG(sig)
                        if sig.type_covered == u16::from(RecordType::DNAME))
                })
                .cloned()
                .collect();
            if signatures.is_empty() || signatures.iter().any(|rr| {
                matches!(&rr.rdata, RData::RRSIG(sig) if usize::from(sig.labels) != dname.name.as_ref().len())
            }) {
                continue;
            }
            let dname_question = Question {
                qname: dname.name.clone(),
                qtype: QueryType::DNAME,
                qclass: question.qclass,
            };
            // A cached source was already authenticated with its own absolute
            // deadline. Reconstructing its expiry from a floored wire TTL on
            // every unrelated target miss would drain seconds per query.
            // Never apply this to network-origin, replaced, or expired data.
            let retained = sources.iter().any(|source| {
                source.question.qname.eq_dns(&dname_question.qname)
                    && source.question.qclass == dname_question.qclass
                    && self
                        .positive_cache
                        .retain_question(&dname_question, &source.identity)
                        .is_some_and(|selected| {
                            selected.is_live()
                                && selected.answers().len() == signatures.len() + 1
                                && selected.answers().iter().all(|old| {
                                    old.eq_dns(dname)
                                        || signatures.iter().any(|sig| old.eq_dns(sig))
                                })
                        })
            });
            if retained {
                continue;
            }
            let mut headers = response.headers.clone();
            headers.rcode = RCode::Ok;
            headers.rd = false;
            // This projected RRset was individually authenticated, even
            // when another part of the combined answer was insecure.
            headers.ad = true;
            let mut answers = vec![dname.clone()];
            answers.extend(signatures);
            let now = Instant::now();
            let deadline = evidence.map(|entry| entry.deadline).unwrap_or_else(|| {
                let ttl = answers.iter().map(|answer| answer.ttl).min().unwrap_or(0);
                observed_at
                    .checked_add(Duration::from_secs(u64::from(ttl)))
                    .unwrap_or(observed_at)
            });
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                continue;
            }
            // Wire TTL zero can mean a live subsecond RRset. Only the cache
            // projection uses this positive placeholder; the inserted entry
            // is capped at the exact validated absolute deadline below.
            let seconds = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                .min(u64::from(u32::MAX)) as u32;
            for answer in &mut answers {
                answer.ttl = seconds;
            }
            let projected = Message {
                headers,
                questions: vec![dname_question.clone()],
                answers,
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            self.cache_positive_entries_at(
                response.headers.id,
                &projected,
                &dname_question,
                now,
                Some(deadline),
            );
        }
    }

    /// Select the closest live authenticated ancestor. A live child delegation
    /// can only veto use: it is never treated as authenticated by this path.
    #[cfg(test)]
    pub(in crate::resolver) fn select_cached_dname(
        &self,
        question: &Question,
    ) -> Option<CachedDname> {
        self.select_cached_dname_with_cut(question, None)
    }

    pub(in crate::resolver) fn select_cached_dname_with_cut(
        &self,
        question: &Question,
        fresh_cut: Option<&DomainName>,
    ) -> Option<CachedDname> {
        let _policy = self.cache_policy.lock().unwrap_or_else(|e| e.into_inner());
        self.select_cached_dname_locked(question, fresh_cut)
    }

    /// The caller holds the policy lock across every component selection.
    pub(in crate::resolver::cache) fn select_cached_dname_locked(
        &self,
        question: &Question,
        fresh_cut: Option<&DomainName>,
    ) -> Option<CachedDname> {
        let QClassType::Class(class) = question.qclass else {
            return None;
        };
        if question
            .qname
            .as_ref()
            .iter()
            .any(|label| label.as_slice() == b"*")
        {
            return None;
        }
        // DS at a cut is parent-side, but a delegation below a cached DNAME
        // still vetoes synthesis. A neutral A lookup includes that exact cut.
        let mut delegation_question = question.clone();
        delegation_question.qtype = QueryType::A;
        let cut = self
            .delegation_cache
            .get(&delegation_question)
            .map(|d| d.zone);
        let labels = question.qname.as_ref();
        for first in 1..=labels.len() {
            let owner = DomainName::from_labels(labels[first..].to_vec()).ok()?;
            let lookup = Question {
                qname: owner.clone(),
                qtype: QueryType::DNAME,
                qclass: question.qclass,
            };
            let Some(selected) = self.positive_cache.select_question(&lookup) else {
                continue;
            };
            if !selected.authenticated {
                return None;
            }
            // Ordinary direct DNAME queries can also populate this cache.
            // Apply the same wildcard restriction at selection as admission.
            let mut signatures = selected.answers().iter().filter_map(|rr| {
                if rr.rtype == RecordType::RRSIG
                    && rr.class == class
                    && rr.name.eq_dns(&owner)
                    && let RData::RRSIG(sig) = &rr.rdata
                    && sig.type_covered == u16::from(RecordType::DNAME)
                {
                    Some(sig)
                } else {
                    None
                }
            });
            let first = signatures.next()?;
            if usize::from(first.labels) != owner.as_ref().len()
                || signatures.any(|sig| usize::from(sig.labels) != owner.as_ref().len())
            {
                return None;
            }
            if cut
                .as_ref()
                .is_some_and(|zone| !zone.eq_dns(&owner) && zone.is_descendant_of(&owner))
                || fresh_cut.is_some_and(|zone| {
                    !zone.eq_dns(&owner)
                        && zone.is_descendant_of(&owner)
                        && question.qname.is_descendant_of(zone)
                })
            {
                return None;
            }
            let dname = selected.answers().iter().find(|rr| {
                rr.name.eq_dns(&owner)
                    && rr.class == class
                    && matches!(rr.rdata, RData::DNAME(_))
                    && rr.rtype == RecordType::DNAME
            })?;
            let RData::DNAME(destination) = &dname.rdata else {
                unreachable!()
            };
            let target = question
                .qname
                .dname_substitute(&owner, destination)
                .map(|result| result.expect("selected owner is a strict ancestor"));
            return Some(CachedDname {
                selection: selected,
                question: lookup,
                target,
            });
        }
        None
    }
}

/// Do not promote an unrelated but validly signed answer RRset into the
/// cache. Follow only the alias path connected to the client's question.
fn connected_dnames<'a>(
    response: &'a Message,
    question: &Question,
    class: dns::ClassType,
    max_steps: usize,
) -> Vec<&'a dns::ResourceRecord> {
    let mut current = question.qname.clone();
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    loop {
        if seen.len() >= max_steps {
            return Vec::new();
        }
        if !seen.insert(current.clone()) {
            return Vec::new();
        }
        let mut candidates = response.answers.iter().filter(|rr| {
            rr.class == class
                && rr.rtype == RecordType::DNAME
                && matches!(rr.rdata, RData::DNAME(_))
                && current.is_descendant_of(&rr.name)
                && !current.eq_dns(&rr.name)
        });
        let dname = candidates.next();
        if candidates.next().is_some() {
            return Vec::new();
        }
        let mut cnames = response.answers.iter().filter_map(|rr| {
            if rr.class == class
                && rr.rtype == RecordType::CNAME
                && rr.name.eq_dns(&current)
                && let RData::CNAME(target) = &rr.rdata
            {
                return Some(target);
            }
            None
        });
        let cname = cnames.next();
        if cnames.next().is_some() {
            return Vec::new();
        }
        if let Some(dname) = dname {
            let RData::DNAME(destination) = &dname.rdata else {
                unreachable!()
            };
            match current.dname_substitute(&dname.name, destination) {
                Ok(Some(target)) if cname.is_some_and(|value| value.eq_dns(&target)) => {
                    result.push(dname);
                }
                Err(_) if response.headers.rcode == RCode::YXDomain && cname.is_none() => {
                    result.push(dname);
                    return result;
                }
                _ => return Vec::new(),
            }
        }
        if matches!(question.qtype, QueryType::CNAME | QueryType::ANY) {
            return result;
        }
        let Some(target) = cname else { return result };
        current = target.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{ClassType, Headers, ResourceRecord};

    fn name(s: &str) -> DomainName {
        DomainName::from_dotted(s).unwrap()
    }
    fn record(owner: &str, rdata: RData) -> ResourceRecord {
        let rtype = match rdata {
            RData::CNAME(_) => RecordType::CNAME,
            RData::DNAME(_) => RecordType::DNAME,
            _ => unreachable!(),
        };
        ResourceRecord {
            name: name(owner),
            rtype,
            class: ClassType::IN,
            ttl: 60,
            rdata,
        }
    }
    #[test]
    fn projects_only_connected_bounded_dnames_and_rejects_malformed_chains() {
        let q = Question {
            qname: name("one.old.example."),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        let dname = record("old.example.", RData::DNAME(name("new.example.")));
        let unrelated = record("other.example.", RData::DNAME(name("else.example.")));
        let cname = record("one.old.example.", RData::CNAME(name("one.new.example.")));
        let mut response = Message {
            headers: Headers {
                qr: true,
                ..Headers::default()
            },
            questions: vec![q.clone()],
            answers: vec![dname.clone(), unrelated, cname],
            authorities: vec![],
            additionals: vec![],
        };
        assert_eq!(connected_dnames(&response, &q, ClassType::IN, 8).len(), 1);
        assert!(connected_dnames(&response, &q, ClassType::IN, 1).is_empty());
        response.answers[2].rdata = RData::CNAME(name("wrong.example."));
        assert!(connected_dnames(&response, &q, ClassType::IN, 8).is_empty());
        response.answers[2].rdata = RData::CNAME(name("one.new.example."));
        response
            .answers
            .push(record("one.new.example.", RData::CNAME(q.qname.clone())));
        assert!(connected_dnames(&response, &q, ClassType::IN, 8).is_empty());
        response.answers.push(dname);
        assert!(connected_dnames(&response, &q, ClassType::IN, 8).is_empty());
    }
}

use crate::{
    CacheCategory, CacheEntryFamily, CacheEntryKey, CacheRead, CacheReadPlan, cache::codec::invalid,
};
use dns::{DomainName, QClassType, Question, RData, ResourceRecord};
use std::{collections::HashSet, io};
pub(super) const CATEGORIES: [CacheCategory; 6] = [
    CacheCategory::Positive,
    CacheCategory::Negative,
    CacheCategory::Delegation,
    CacheCategory::Bad,
    CacheCategory::Failure,
    CacheCategory::AuthenticatedKeys,
];
pub(in crate::resolver) fn zone(name: &DomainName, class: dns::ClassType) -> Question {
    Question {
        qname: name.clone(),
        qtype: dns::QueryType::A,
        qclass: QClassType::Class(class),
    }
}
pub(in crate::resolver) fn seeds_many(
    response: &dns::Message,
    questions: &[&Question],
) -> Vec<Question> {
    let mut out = Vec::new();
    for q in questions {
        out.extend(seeds(response, q));
    }
    out
}
pub(in crate::resolver) fn seeds(response: &dns::Message, question: &Question) -> Vec<Question> {
    let mut out = vec![question.clone()];
    for rr in response.answers.iter().chain(&response.authorities) {
        out.push(Question {
            qname: rr.name.clone(),
            qclass: QClassType::Class(rr.class),
            qtype: dns::QueryType::A,
        });
    }
    out
}
pub(super) fn expand(
    names: &mut Vec<Question>,
    links: &[ResourceRecord],
    maximum: usize,
) -> io::Result<()> {
    let previous = names.clone();
    for q in previous {
        for rr in links {
            if q.qclass.value() != rr.class.value() {
                continue;
            }
            let target = match &rr.rdata {
                RData::CNAME(target) if rr.name.eq_dns(&q.qname) => Some(target.clone()),
                RData::DNAME(target) => q.qname.dname_substitute(&rr.name, target).ok().flatten(),
                _ => None,
            };
            if let Some(qname) = target
                && !names
                    .iter()
                    .any(|x| x.qname.eq_dns(&qname) && x.qclass == q.qclass)
            {
                if names.len() >= maximum {
                    return Err(invalid());
                }
                names.push(Question { qname, ..q.clone() })
            }
        }
    }
    Ok(())
}
pub(super) fn pending(
    names: &[Question],
    seen: &mut HashSet<CacheEntryFamily>,
    max_entries: usize,
    max_bytes: usize,
) -> io::Result<CacheReadPlan> {
    let mut reads = Vec::new();
    for q in names {
        let QClassType::Class(class) = q.qclass else {
            continue;
        };
        for at in 0..=q.qname.as_ref().len() {
            let owner =
                DomainName::from_labels(q.qname.as_ref()[at..].to_vec()).map_err(|_| invalid())?;
            let owner = crate::name::packed_key(&owner).to_vec();
            for category in CATEGORIES {
                let f = CacheEntryFamily {
                    category,
                    owner: owner.clone(),
                    class: class.value(),
                };
                if seen.insert(f.clone()) {
                    reads.push(CacheRead::OwnerFamily(f));
                }
            }
        }
    }
    if seen.len() > 8192 {
        return Err(invalid());
    }
    Ok(CacheReadPlan {
        reads,
        maximum_entries: max_entries,
        maximum_bytes: max_bytes,
    })
}
pub(super) fn matches(key: &CacheEntryKey, read: &CacheRead) -> bool {
    match read {
        CacheRead::Exact(x) => key == x,
        CacheRead::OwnerFamily(x) => &key.family == x,
        CacheRead::Ancestors(x) => {
            key.family.category == x.category
                && key.family.class == x.class
                && suffix(&x.owner, &key.family.owner)
        }
        CacheRead::DenialCandidates(_) => false,
    }
}
fn suffix(name: &[u8], parent: &[u8]) -> bool {
    let mut at = 0;
    loop {
        if &name[at..] == parent {
            return true;
        }
        if name.get(at) == Some(&0) {
            return false;
        }
        let Some(n) = name.get(at) else { return false };
        at += 1 + usize::from(*n);
        if at >= name.len() {
            return false;
        }
    }
}

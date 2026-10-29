//! Prepare and validate authority for every DNAME hop in one response.
use super::boundaries::{
    applicable_child_delegation, delegation_covers_name, dname_owner_within_authority,
};
use crate::response::{checked_substitution, prepare_substitution};
use dns::{DomainName, Message, QueryType, Question, RData, RecordType};
use std::collections::{HashMap, HashSet};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PreparedChain {
    NoDname,
    Redirect,
    Overflow(DomainName),
}

/// This performs no DNSSEC authentication or cache admission. Callers must
/// still validate all retained DNAME RRsets before returning a secure answer.
pub(super) fn prepare_chain(
    reply: &mut Message,
    question: &Question,
    zone: &DomainName,
) -> Result<PreparedChain, ()> {
    let mut current = question.qname.clone();
    let mut seen = HashSet::new();
    let mut redirected = false;
    loop {
        if !seen.insert(current.clone()) {
            return Err(());
        }
        if !current.is_descendant_of(zone) {
            break;
        }
        let step = Question {
            qname: current.clone(),
            ..question.clone()
        };
        if applicable_child_delegation(reply, &step, zone).is_some() {
            break;
        }
        match checked_substitution(&reply.answers, &step, zone) {
            Ok(Some((dname, _))) => {
                if !dname_owner_within_authority(dname, &step, zone, reply) {
                    return Err(());
                }
                prepare_substitution(&mut reply.answers, &step, zone).map_err(|_| ())?;
                redirected = true;
            }
            Ok(None) => {}
            Err(crate::response::DnameError::Overflow) => {
                let candidates: Vec<_> = reply
                    .answers
                    .iter()
                    .filter(|rr| {
                        rr.rtype == RecordType::DNAME
                            && rr.class.value() == question.qclass.value()
                            && current.is_descendant_of(&rr.name)
                            && !current.eq_dns(&rr.name)
                    })
                    .collect();
                if candidates.len() != 1
                    || !dname_owner_within_authority(candidates[0], &step, zone, reply)
                {
                    return Err(());
                }
                return Ok(PreparedChain::Overflow(current));
            }
            Err(_) => return Err(()),
        }
        if matches!(question.qtype, QueryType::CNAME | QueryType::ANY) {
            break;
        }
        let target = reply.answers.iter().find_map(|rr| {
            if rr.class.value() == question.qclass.value()
                && rr.name.eq_dns(&current)
                && rr.rtype == RecordType::CNAME
                && let RData::CNAME(target) = &rr.rdata
            {
                return Some(target.clone());
            }
            None
        });
        match target {
            Some(target) if delegation_covers_name(zone, &target) => current = target,
            Some(_) => break,
            None => break,
        }
    }
    Ok(if redirected {
        PreparedChain::Redirect
    } else {
        PreparedChain::NoDname
    })
}

/// Checks the response shape for a DNAME overflow. Cryptographic validation
/// and retention of the DNAME proof remain the caller's responsibility.
pub(super) fn is_overflow_response(
    reply: &Message,
    question: &Question,
    zone: &DomainName,
) -> bool {
    if !reply.headers.qr || !reply.headers.aa || reply.headers.rcode != dns::RCode::YXDomain {
        return false;
    }
    let mut prepared = reply.clone();
    let Ok(PreparedChain::Overflow(overflow_name)) = prepare_chain(&mut prepared, question, zone)
    else {
        return false;
    };
    let mut current = question.qname.clone();
    let mut visited = HashSet::new();
    let mut dname_owners = HashSet::new();
    let mut cname_owners = HashMap::new();
    let mut synthesized = HashSet::new();
    loop {
        if !visited.insert(current.clone()) {
            return false;
        }
        let step = Question {
            qname: current.clone(),
            ..question.clone()
        };
        if let Some(dname) = prepared.answers.iter().find(|rr| {
            rr.rtype == RecordType::DNAME
                && rr.class.value() == question.qclass.value()
                && current.is_descendant_of(&rr.name)
                && !current.eq_dns(&rr.name)
        }) {
            dname_owners.insert(dname.name.clone());
            if !current.eq_dns(&overflow_name) {
                synthesized.insert(current.clone());
            }
        }
        if current.eq_dns(&overflow_name) {
            break;
        }
        let Some(target) = prepared.answers.iter().find_map(|rr| {
            if rr.rtype == RecordType::CNAME
                && rr.class.value() == step.qclass.value()
                && rr.name.eq_dns(&current)
                && let RData::CNAME(target) = &rr.rdata
            {
                return Some(target.clone());
            }
            None
        }) else {
            return false;
        };
        cname_owners.insert(current, target.clone());
        current = target;
    }
    reply.answers.iter().all(|record| {
        if record.class.value() != question.qclass.value() {
            return false;
        }
        match &record.rdata {
            RData::DNAME(_) if record.rtype == RecordType::DNAME => {
                dname_owners.contains(&record.name)
            }
            RData::CNAME(target) if record.rtype == RecordType::CNAME => cname_owners
                .get(&record.name)
                .is_some_and(|expected| expected.eq_dns(target)),
            RData::RRSIG(sig) if record.rtype == RecordType::RRSIG => {
                (sig.type_covered == u16::from(RecordType::DNAME)
                    && dname_owners.contains(&record.name))
                    || (sig.type_covered == u16::from(RecordType::CNAME)
                        && cname_owners.contains_key(&record.name)
                        && !synthesized.contains(&record.name))
            }
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{ClassType, Headers, QClassType, ResourceRecord};
    fn name(s: &str) -> DomainName {
        DomainName::from_dotted(s).unwrap()
    }
    fn question(s: &str) -> Question {
        Question {
            qname: name(s),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }
    }
    fn dname(owner: &str, target: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name(owner),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl,
            rdata: RData::DNAME(name(target)),
        }
    }
    fn packet(answers: Vec<ResourceRecord>) -> Message {
        Message {
            headers: Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            questions: vec![],
            answers,
            authorities: vec![],
            additionals: vec![],
        }
    }
    #[test]
    fn synthesizes_multiple_in_zone_hops_and_retains_zero_ttl() {
        let mut reply = packet(vec![
            dname("old.example", "new.example", 0),
            dname("new.example", "last.other", 60),
        ]);
        assert_eq!(
            prepare_chain(&mut reply, &question("www.old.example"), &name("example")),
            Ok(PreparedChain::Redirect)
        );
        let aliases: Vec<_> = reply
            .answers
            .iter()
            .filter(|r| r.rtype == RecordType::CNAME)
            .collect();
        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases[0].ttl, 0);
        assert!(
            matches!(&aliases[1].rdata, RData::CNAME(target) if target.eq_dns(&name("www.last.other")))
        );
    }
    #[test]
    fn rejects_forged_cname_and_out_of_authority_owner() {
        let mut reply = packet(vec![
            dname("example", "new.other", 30),
            ResourceRecord {
                name: name("www.example"),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 30,
                rdata: RData::CNAME(name("wrong.other")),
            },
        ]);
        assert!(prepare_chain(&mut reply, &question("www.example"), &name("example")).is_err());
        let mut reply = packet(vec![dname("example", "new.other", 30)]);
        assert!(
            prepare_chain(
                &mut reply,
                &question("www.child.example"),
                &name("child.example")
            )
            .is_err()
        );
    }
    #[test]
    fn refuses_dname_below_advertised_delegation() {
        let mut reply = packet(vec![dname("old.child.example", "new.other", 30)]);
        reply.authorities.push(ResourceRecord {
            name: name("child.example"),
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::NS(name("ns.other")),
        });
        assert_eq!(
            prepare_chain(
                &mut reply,
                &question("www.old.child.example"),
                &name("example")
            ),
            Ok(PreparedChain::NoDname)
        );
        assert_eq!(reply.answers.len(), 1);
    }
    #[test]
    fn overflow_rejects_conflicting_cname_targets_at_a_prior_hop() {
        let target = DomainName::from_labels(vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 60],
        ])
        .unwrap();
        let mut rr = dname("old.example", "new.other", 30);
        rr.rdata = RData::DNAME(target);
        let alias = ResourceRecord {
            name: name("alias.example"),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::CNAME(name("prefix.old.example")),
        };
        let mut reply = packet(vec![alias.clone(), rr]);
        reply.headers.rcode = dns::RCode::YXDomain;
        assert!(is_overflow_response(
            &reply,
            &question("alias.example"),
            &name("example")
        ));
        let mut forged = alias;
        forged.rdata = RData::CNAME(name("wrong.example"));
        reply.answers.push(forged);
        assert!(!is_overflow_response(
            &reply,
            &question("alias.example"),
            &name("example")
        ));
    }

    #[test]
    fn reports_checked_name_overflow() {
        let target = DomainName::from_labels(vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 60],
        ])
        .unwrap();
        let mut rr = dname("old.example", "new.other", 30);
        rr.rdata = RData::DNAME(target);
        let mut reply = packet(vec![rr]);
        assert_eq!(
            prepare_chain(
                &mut reply,
                &question("prefix.old.example"),
                &name("example")
            ),
            Ok(PreparedChain::Overflow(name("prefix.old.example")))
        );
        reply.headers.rcode = dns::RCode::YXDomain;
        assert!(is_overflow_response(
            &reply,
            &question("prefix.old.example"),
            &name("example")
        ));
        reply.headers.aa = false;
        assert!(!is_overflow_response(
            &reply,
            &question("prefix.old.example"),
            &name("example")
        ));
        reply.headers.aa = true;
        reply.headers.rcode = dns::RCode::Ok;
        assert!(!is_overflow_response(
            &reply,
            &question("prefix.old.example"),
            &name("example")
        ));
        reply.headers.rcode = dns::RCode::YXDomain;
        let clean = reply.clone();
        for unrelated in [
            ResourceRecord {
                name: name("elsewhere.example"),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 30,
                rdata: RData::CNAME(name("other.example")),
            },
            dname("elsewhere.example", "other.example", 30),
            ResourceRecord {
                name: name("elsewhere.example"),
                rtype: RecordType::RRSIG,
                class: ClassType::IN,
                ttl: 30,
                rdata: RData::RRSIG(dns::Rrsig {
                    type_covered: 39,
                    algorithm: 8,
                    labels: 2,
                    original_ttl: 30,
                    signature_expiration: 100,
                    signature_inception: 1,
                    key_tag: 1,
                    signer_name: name("example"),
                    signature: vec![1],
                }),
            },
        ] {
            let mut malicious = clean.clone();
            malicious.answers.push(unrelated);
            assert!(!is_overflow_response(
                &malicious,
                &question("prefix.old.example"),
                &name("example")
            ));
        }
        reply.answers.push(ResourceRecord {
            name: name("prefix.old.example"),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::CNAME(name("forged.other")),
        });
        assert!(!is_overflow_response(
            &reply,
            &question("prefix.old.example"),
            &name("example")
        ));
    }
}

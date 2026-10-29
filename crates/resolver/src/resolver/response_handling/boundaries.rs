use dns::{DomainName, Message, Question, RData, RecordType};

pub(super) fn delegation_covers_name(zone: &DomainName, name: &DomainName) -> bool {
    !zone.as_ref().is_empty() && name.is_descendant_of(zone)
}

/// Checks a DNAME owner against the server's current authority and any child
/// delegation explicitly advertised in the same response. Signature
/// validation and authenticated delegation history remain separate checks.
pub(super) fn dname_owner_within_authority(
    dname: &dns::ResourceRecord,
    question: &Question,
    delegation_zone: &DomainName,
    reply: &Message,
) -> bool {
    if question.qclass != dns::QClassType::Class(dname.class)
        || !dname.name.is_descendant_of(delegation_zone)
    {
        return false;
    }
    let owner_question = Question {
        qname: dname.name.clone(),
        qtype: dns::QueryType::A,
        qclass: question.qclass,
    };
    applicable_child_delegation(reply, &owner_question, delegation_zone).is_none()
}

/// Finds the closest child cut that covers `question` in this response.
///
/// NS records at the current zone apex describe the current authority rather
/// than a cut. DS at the exact child apex is deliberately excluded because it
/// is authoritative parent-side data; names below the cut (including DS
/// queries) are still child-side.
pub(super) fn applicable_child_delegation<'a>(
    reply: &'a Message,
    question: &Question,
    current_zone: &DomainName,
) -> Option<&'a DomainName> {
    let dns::QClassType::Class(class) = question.qclass else {
        return None;
    };
    reply
        .authorities
        .iter()
        .filter(|record| {
            record.rtype == RecordType::NS
                && matches!(record.rdata, RData::NS(_))
                && record.class == class
                && record.name.is_descendant_of(current_zone)
                && !record.name.eq_dns(current_zone)
                && question.qname.is_descendant_of(&record.name)
                && !(question.qtype == dns::QueryType::DS && question.qname.eq_dns(&record.name))
        })
        .map(|record| &record.name)
        .max_by_key(|name| name.as_ref().len())
}

/// Returns the authoritative prefix ending at the first authority boundary.
///
/// The crossing CNAME itself is retained because its owner is covered by the
/// current delegation. Records owned by that target and later names are not.
pub(super) fn trusted_cname_prefix(
    chain_records: &[dns::ResourceRecord],
    question: &Question,
    delegation_zone: &DomainName,
    reply: &Message,
) -> Option<(Vec<dns::ResourceRecord>, DomainName)> {
    let mut owner = question.qname.clone();
    let mut prefix = Vec::new();
    loop {
        let cname = chain_records
            .iter()
            .find(|record| record.name.eq_dns(&owner) && matches!(record.rdata, RData::CNAME(_)))?;
        let RData::CNAME(target) = &cname.rdata else {
            unreachable!("the record was matched as a CNAME")
        };
        if let Some(dname) = chain_records.iter().find(|record| {
            record.class == cname.class
                && matches!(&record.rdata, RData::DNAME(destination)
                    if owner.dname_substitute(&record.name, destination)
                        .ok().flatten().is_some_and(|derived| derived.eq_dns(target)))
        }) {
            prefix.push(dname.clone());
            prefix.extend(
                chain_records
                    .iter()
                    .filter(|record| {
                        record.class == dname.class
                            && record.name.eq_dns(&dname.name)
                            && matches!(&record.rdata, RData::RRSIG(sig)
                        if sig.type_covered == u16::from(RecordType::DNAME))
                    })
                    .cloned(),
            );
        }
        prefix.extend(
            chain_records
                .iter()
                .filter(|record| record.name.eq_dns(&owner))
                .cloned(),
        );
        let target_question = Question {
            qname: target.clone(),
            ..question.clone()
        };
        if !delegation_covers_name(delegation_zone, target)
            || applicable_child_delegation(reply, &target_question, delegation_zone).is_some()
        {
            return Some((prefix, target.clone()));
        }
        owner = target.clone();
    }
}

#[cfg(test)]
mod tests {
    use dns::{ClassType, Headers, QClassType, QueryType, ResourceRecord};

    use super::*;

    fn name(labels: &[&str]) -> DomainName {
        DomainName::from_labels(
            labels
                .iter()
                .map(|label| label.as_bytes().to_vec())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn dname_owner_must_be_in_authority_and_above_no_advertised_child_cut() {
        let dname = ResourceRecord {
            name: name(&["old", "child", "example"]),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::DNAME(name(&["new", "other"])),
        };
        let question = Question {
            qname: name(&["www", "old", "child", "example"]),
            qtype: QueryType::DS,
            qclass: QClassType::Class(ClassType::IN),
        };
        let mut reply = Message {
            headers: Headers::default(),
            questions: vec![],
            answers: vec![dname.clone()],
            authorities: vec![],
            additionals: vec![],
        };
        assert!(dname_owner_within_authority(
            &dname,
            &question,
            &name(&["example"]),
            &reply
        ));
        assert!(!dname_owner_within_authority(
            &dname,
            &question,
            &name(&["other"]),
            &reply
        ));
        reply.authorities.push(ResourceRecord {
            name: name(&["child", "example"]),
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::NS(name(&["ns", "other"])),
        });
        assert!(!dname_owner_within_authority(
            &dname,
            &question,
            &name(&["example"]),
            &reply
        ));
    }

    #[test]
    fn crossing_dname_keeps_its_proof_with_the_cname() {
        let owner = name(&["old", "example"]);
        let qname = name(&["www", "old", "example"]);
        let target = name(&["www", "new", "other"]);
        let chain = vec![
            ResourceRecord {
                name: owner.clone(),
                rtype: RecordType::DNAME,
                class: ClassType::IN,
                ttl: 30,
                rdata: RData::DNAME(name(&["new", "other"])),
            },
            ResourceRecord {
                name: qname.clone(),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 30,
                rdata: RData::CNAME(target.clone()),
            },
        ];
        let question = Question {
            qname,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        let reply = Message {
            headers: Headers::default(),
            questions: vec![],
            answers: chain.clone(),
            authorities: vec![],
            additionals: vec![],
        };
        let (prefix, crossed) =
            trusted_cname_prefix(&chain, &question, &name(&["example"]), &reply).unwrap();
        assert!(crossed.eq_dns(&target));
        assert_eq!(
            prefix.iter().map(|r| r.rtype).collect::<Vec<_>>(),
            vec![RecordType::DNAME, RecordType::CNAME]
        );
    }

    #[test]
    fn child_cut_excludes_child_data_but_not_parent_side_ds() {
        let parent = name(&["example"]);
        let child = name(&["child", "example"]);
        let reply = Message {
            headers: Headers::default(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: vec![ResourceRecord {
                name: child.clone(),
                rtype: RecordType::NS,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::NS(name(&["ns", "child", "example"])),
            }],
            additionals: Vec::new(),
        };
        let question = |qname, qtype| Question {
            qname,
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        };

        assert!(
            applicable_child_delegation(
                &reply,
                &question(name(&["www", "child", "example"]), QueryType::A),
                &parent,
            )
            .is_some()
        );
        assert!(
            applicable_child_delegation(&reply, &question(child.clone(), QueryType::A), &parent,)
                .is_some()
        );
        assert!(
            applicable_child_delegation(&reply, &question(child, QueryType::DS), &parent,)
                .is_none()
        );
    }
}

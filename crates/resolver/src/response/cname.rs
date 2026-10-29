use dns::{ClassType, DomainName, Message, QClassType, QueryType, Question, RData, ResourceRecord};

use crate::name::NameSet;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum CnameError {
    Loop,
    MultipleTargets,
    CoexistingData,
    InvalidDname,
}

/// Validates CNAME exclusivity and finds the canonical restart point.
pub(crate) fn cname_restart(
    answers: &[ResourceRecord],
    question: &Question,
) -> Result<Option<(Vec<ResourceRecord>, DomainName)>, CnameError> {
    let class = match question.qclass {
        QClassType::Class(class) => class,
        QClassType::ANY | QClassType::Unknown(_) => return Ok(None),
    };
    validate_cname_records(answers, class)?;
    if matches!(question.qtype, QueryType::CNAME | QueryType::ANY) {
        return Ok(None);
    }

    let mut chain = Vec::new();
    let mut current = question.qname.clone();
    let mut visited = NameSet::from_name(&current);
    while let Some(record) = answers.iter().find(|record| {
        record.class == class
            && record.name.eq_dns(&current)
            && matches!(&record.rdata, RData::CNAME(_))
    }) {
        let step = Question {
            qname: current.clone(),
            ..question.clone()
        };
        let dname = super::checked_substitution(answers, &step, &DomainName::root())
            .map_err(|_| CnameError::InvalidDname)?;
        let RData::CNAME(target) = &record.rdata else {
            unreachable!("the record was matched as a CNAME")
        };
        if !visited.insert(target.clone()) {
            return Err(CnameError::Loop);
        }
        if let Some((dname, _)) = dname {
            append_distinct(&mut chain, std::iter::once(dname.clone()));
            append_distinct(&mut chain, answers.iter().filter(|candidate| {
                candidate.class == dname.class && candidate.name.eq_dns(&dname.name)
                    && matches!(&candidate.rdata, RData::RRSIG(sig) if sig.type_covered == u16::from(dns::RecordType::DNAME))
            }).cloned());
        }
        chain.push(record.clone());
        chain.extend(
            answers
                .iter()
                .filter(|other| {
                    other.class == class
                        && other.name.eq_dns(&record.name)
                        && other.rtype.is_cname_companion()
                })
                .cloned(),
        );
        current = target.clone();
    }
    Ok((!chain.is_empty()).then_some((chain, current)))
}

/// Preserve first-seen order while never extending a repeated record's TTL.
pub(crate) fn append_distinct(
    records: &mut Vec<ResourceRecord>,
    incoming: impl IntoIterator<Item = ResourceRecord>,
) {
    for record in incoming {
        if let Some(existing) = records.iter_mut().find(|old| old.eq_dns(&record)) {
            existing.ttl = existing.ttl.min(record.ttl);
        } else {
            records.push(record);
        }
    }
}

pub(super) fn validate_cname_records(
    answers: &[ResourceRecord],
    class: ClassType,
) -> Result<(), CnameError> {
    for record in answers
        .iter()
        .filter(|record| record.class == class && matches!(record.rdata, RData::CNAME(_)))
    {
        let RData::CNAME(target) = &record.rdata else {
            unreachable!("the record was matched as a CNAME")
        };
        for other in answers
            .iter()
            .filter(|other| other.class == class && other.name.eq_dns(&record.name))
        {
            match &other.rdata {
                RData::CNAME(other_target) if !other_target.eq_dns(target) => {
                    return Err(CnameError::MultipleTargets);
                }
                RData::CNAME(_) => {}
                _ if other.rtype.is_cname_companion() => {}
                _ => return Err(CnameError::CoexistingData),
            }
        }
    }
    Ok(())
}

pub(crate) fn complete_cname_response(
    mut reply: Message,
    original_question: &Question,
    mut cname_answers: Vec<ResourceRecord>,
    cname_authorities: Vec<ResourceRecord>,
) -> Message {
    for record in cname_authorities {
        if let Some(existing) = reply.authorities.iter_mut().find(|existing| {
            existing.name.eq_dns(&record.name)
                && existing.class == record.class
                && existing.rtype == record.rtype
                && existing.rdata == record.rdata
        }) {
            existing.ttl = existing.ttl.min(record.ttl);
        } else {
            reply.authorities.push(record);
        }
    }
    if cname_answers.is_empty() {
        return reply;
    }

    if cname_answers
        .iter()
        .chain(&reply.answers)
        .any(|rr| rr.rtype == dns::RecordType::DNAME)
    {
        append_distinct(&mut cname_answers, reply.answers.drain(..));
    } else {
        cname_answers.append(&mut reply.answers);
    }
    reply.answers = cname_answers;
    reply.questions.clear();
    reply.questions.push(original_question.clone());
    // The final answer may be authoritative only for the CNAME target, not
    // necessarily for the original question.
    reply.headers.aa = false;
    reply
}

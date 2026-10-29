use std::collections::HashSet;

use dns::{Message, QClassType, QueryType, Question, RCode, RData, ResourceRecord};

use crate::name::NameSet;

use super::{classification::query_type_matches_record, cname::validate_cname_records};

/// Builds positive cache entries for the requested CNAME path and
/// its matching terminal RRsets, retaining wildcard denial proofs as authority
/// data. Unrelated records cannot be promoted to answers.
/// CNAMEs remain positive cache material when the canonical target is negative.
pub(crate) fn positive_cache_entries(
    reply: &Message,
    question: &Question,
) -> Vec<(Question, Message)> {
    let QClassType::Class(class) = question.qclass else {
        return Vec::new();
    };
    // The ordinary alias cache stores CNAMEs independently of ancestors.
    // Until DNAME proof and lifetime are retained with each derived alias,
    // never admit a response that may contain such an alias through that path.
    if reply
        .answers
        .iter()
        .any(|r| r.rtype == dns::RecordType::DNAME)
        && reply
            .answers
            .iter()
            .any(|r| r.rtype == dns::RecordType::CNAME)
    {
        return Vec::new();
    }
    if !matches!(reply.headers.rcode, RCode::Ok | RCode::NameError)
        || question
            .qname
            .as_ref()
            .iter()
            .any(|label| label.as_slice() == b"*")
        || validate_cname_records(&reply.answers, class).is_err()
    {
        return Vec::new();
    }

    let follow_cname = !matches!(question.qtype, QueryType::CNAME | QueryType::ANY);
    let mut current = question.qname.clone();
    let mut chain = Vec::new();
    if follow_cname {
        let mut visited = NameSet::from_name(&current);
        while let Some(record) = reply.answers.iter().find(|record| {
            record.class == class
                && record.name.eq_dns(&current)
                && record.rtype == dns::RecordType::CNAME
        }) {
            let RData::CNAME(target) = &record.rdata else {
                unreachable!("the record was matched as a CNAME")
            };
            if !visited.insert(target.clone()) {
                return Vec::new();
            }
            chain.push(record.clone());
            current = target.clone();
        }
    }

    let mut entries = Vec::new();
    for cname in &chain {
        let cname_question = Question {
            qname: cname.name.clone(),
            qtype: QueryType::CNAME,
            qclass: question.qclass,
        };
        let directly_authoritative = cname.name.eq_dns(&question.qname);
        entries.push((
            cname_question.clone(),
            selected_positive_response(
                reply,
                cname_question,
                vec![cname.clone()],
                directly_authoritative,
            ),
        ));
    }

    let terminal = if reply.headers.rcode == RCode::Ok {
        reply
            .answers
            .iter()
            .filter(|record| {
                record.class == class
                    && record.name.eq_dns(&current)
                    && query_type_matches_record(question.qtype, record.rtype)
            })
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if terminal.is_empty() {
        return entries;
    }

    let terminal_is_direct = chain.is_empty() && current.eq_dns(&question.qname);
    let mut terminal_types = HashSet::new();
    for record in &terminal {
        if !terminal_types.insert(record.rtype) {
            continue;
        }
        let qtype = query_type_for_record(record.rtype);
        let rrset = terminal
            .iter()
            .filter(|candidate| candidate.rtype == record.rtype)
            .cloned()
            .collect();
        let terminal_question = Question {
            qname: current.clone(),
            qtype,
            qclass: question.qclass,
        };
        entries.push((
            terminal_question.clone(),
            selected_positive_response(reply, terminal_question, rrset, terminal_is_direct),
        ));
    }

    if chain.is_empty()
        && terminal_types.len() == 1
        && query_type_for_record(terminal[0].rtype) == question.qtype
    {
        return entries;
    }

    let aggregate_query = matches!(
        question.qtype,
        QueryType::ANY | QueryType::MAILA | QueryType::MAILB
    );
    if reply.headers.aa || !aggregate_query {
        let mut requested_answers = chain;
        requested_answers.extend(terminal);
        entries.push((
            question.clone(),
            selected_positive_response(
                reply,
                question.clone(),
                requested_answers,
                terminal_is_direct,
            ),
        ));
    }
    entries
}

fn selected_positive_response(
    source: &Message,
    question: Question,
    mut answers: Vec<ResourceRecord>,
    directly_authoritative: bool,
) -> Message {
    let covered = answers
        .iter()
        .filter(|record| record.rtype != dns::RecordType::RRSIG)
        .map(|record| (record.name.clone(), record.class, u16::from(record.rtype)))
        .collect::<Vec<_>>();
    let signatures = source
        .answers
        .iter()
        .filter(|record| {
            let RData::RRSIG(rrsig) = &record.rdata else {
                return false;
            };
            !answers.iter().any(|answer| {
                answer.rtype == record.rtype
                    && answer.name.eq_dns(&record.name)
                    && answer.class == record.class
                    && answer.rdata == record.rdata
            }) && covered.iter().any(|(owner, class, rtype)| {
                record.name.eq_dns(owner) && record.class == *class && rrsig.type_covered == *rtype
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    answers.extend(signatures);
    let mut headers = source.headers.clone();
    // Signatures projected out of a validated ANY answer are not themselves
    // authenticated RRsets, even when their covered data was secure.
    if question.qtype == QueryType::RRSIG {
        headers.ad = false;
    }
    headers.aa &= directly_authoritative;
    headers.rcode = RCode::Ok;
    let authorities = super::wildcard_proofs(source, &answers);
    Message {
        headers,
        questions: vec![question],
        answers,
        authorities,
        additionals: Vec::new(),
    }
}

fn query_type_for_record(rtype: dns::RecordType) -> QueryType {
    match rtype {
        dns::RecordType::A => QueryType::A,
        dns::RecordType::NS => QueryType::NS,
        dns::RecordType::MD => QueryType::MD,
        dns::RecordType::MF => QueryType::MF,
        dns::RecordType::CNAME => QueryType::CNAME,
        dns::RecordType::DNAME => QueryType::DNAME,
        dns::RecordType::SOA => QueryType::SOA,
        dns::RecordType::MB => QueryType::MB,
        dns::RecordType::MG => QueryType::MG,
        dns::RecordType::MR => QueryType::MR,
        dns::RecordType::NULL => QueryType::NULL,
        dns::RecordType::WKS => QueryType::WKS,
        dns::RecordType::PTR => QueryType::PTR,
        dns::RecordType::HINFO => QueryType::HINFO,
        dns::RecordType::MINFO => QueryType::MINFO,
        dns::RecordType::MX => QueryType::MX,
        dns::RecordType::TXT => QueryType::TXT,
        dns::RecordType::SIG => QueryType::SIG,
        dns::RecordType::KEY => QueryType::KEY,
        dns::RecordType::AAAA => QueryType::AAAA,
        dns::RecordType::SRV => QueryType::SRV,
        dns::RecordType::CSYNC => QueryType::CSYNC,
        // TSIG is transaction metadata and must never enter the cache.
        dns::RecordType::TSIG => QueryType::Unknown(250),
        dns::RecordType::CAA => QueryType::CAA,
        // OPT is transaction metadata and never reaches cache selection from
        // a valid response. Preserve its numeric identity for permissively
        // decoded malformed input instead of treating it as cacheable data.
        dns::RecordType::OPT => QueryType::Unknown(41),
        dns::RecordType::DS => QueryType::DS,
        dns::RecordType::RRSIG => QueryType::RRSIG,
        dns::RecordType::NSEC => QueryType::NSEC,
        dns::RecordType::DNSKEY => QueryType::DNSKEY,
        dns::RecordType::NSEC3 => QueryType::NSEC3,
        dns::RecordType::NSEC3PARAM => QueryType::NSEC3PARAM,
        dns::RecordType::TLSA => QueryType::TLSA,
        dns::RecordType::SMIMEA => QueryType::SMIMEA,
        dns::RecordType::Unknown(code) => QueryType::Unknown(code),
    }
}

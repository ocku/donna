use dns::{
    ClassType, DomainName, Message, QClassType, QueryType, Question, RCode, RData, ResourceRecord,
};

use crate::ResolveError;

pub(crate) fn validate_question(question: &Question) -> Result<(), ResolveError> {
    let unsupported_class = matches!(
        question.qclass,
        QClassType::ANY | QClassType::Unknown(_) | QClassType::Class(ClassType::Unknown(_))
    );
    let unsupported_type = matches!(
        question.qtype,
        QueryType::IXFR
            | QueryType::AXFR
            | QueryType::Unknown(0 | 1..=16 | 28 | 33 | 39 | 251..=255 | 257 | u16::MAX)
    );
    if unsupported_class || unsupported_type {
        // AXFR and IXFR require transfer-specific state. QCLASS ANY and unknown
        // classes require class-aware delegation state, which this resolver does
        // not claim to support. Noncanonical enum representations are rejected
        // before they can reach the infallible query-building path.
        return Err(ResolveError::UnsupportedQuestion);
    }
    Ok(())
}

pub(crate) fn has_only_negative_answer_metadata(answers: &[ResourceRecord]) -> bool {
    answers.iter().all(|record| {
        record.rtype == dns::RecordType::CNAME || matches!(u16::from(record.rtype), 24 | 46)
    })
}

/// A terminal DNAME negative may contain only an actual checked alias path
/// and its signatures; unrelated positive data is not negative metadata.
pub(crate) fn has_dname_negative_answer_metadata(
    answers: &[ResourceRecord],
    question: &Question,
) -> bool {
    let Ok(Some((chain, _))) = super::cname_restart(answers, question) else {
        return false;
    };
    if !chain
        .iter()
        .any(|record| record.rtype == dns::RecordType::DNAME)
    {
        return false;
    }
    answers.iter().all(|record| {
        let selected = chain.iter().any(|candidate| candidate.eq_dns(record));
        if !selected {
            return false;
        }
        let signature_covers_chain = |covered_type: u16| {
            chain.iter().any(|covered| {
                if !covered.name.eq_dns(&record.name)
                    || covered.class != record.class
                    || !matches!(
                        covered.rtype,
                        dns::RecordType::DNAME | dns::RecordType::CNAME
                    )
                    || u16::from(covered.rtype) != covered_type
                {
                    return false;
                }
                if let RData::CNAME(target) = &covered.rdata {
                    return !chain.iter().any(|dname| {
                        dname.class == covered.class
                            && matches!(&dname.rdata, RData::DNAME(destination)
                            if covered.name.dname_substitute(&dname.name, destination)
                                .ok().flatten().is_some_and(|derived| derived.eq_dns(target)))
                    });
                }
                true
            })
        };
        match &record.rdata {
            RData::DNAME(_) if record.rtype == dns::RecordType::DNAME => true,
            RData::CNAME(_) if record.rtype == dns::RecordType::CNAME => true,
            RData::RRSIG(sig) if record.rtype == dns::RecordType::RRSIG => {
                signature_covers_chain(sig.type_covered)
            }
            RData::SIG(sig) if record.rtype == dns::RecordType::SIG => {
                signature_covers_chain(sig.type_covered)
            }
            _ => false,
        }
    })
}

pub(crate) fn is_terminal_response(reply: &Message, question: &Question) -> bool {
    match reply.headers.rcode {
        RCode::Ok => {
            has_requested_answer(&reply.answers, question)
                || (reply.headers.aa
                    && (has_only_negative_answer_metadata(&reply.answers)
                        || has_dname_negative_answer_metadata(&reply.answers, question))
                    && (has_soa_for_question(reply, question)
                        || !has_ns_for_question_class(reply, question)))
        }
        // RFC 2308 §2.1 permits CNAME and signature records in an NXDOMAIN
        // answer, but ordinary positive data contradicts the Name Error RCODE.
        RCode::NameError => {
            reply.headers.aa
                && (has_only_negative_answer_metadata(&reply.answers)
                    || has_dname_negative_answer_metadata(&reply.answers, question))
        }
        // Server failures and refusals from one delegation host must not prevent
        // trying the other servers in the current SLIST.
        RCode::FormatError
        | RCode::ServerFailure
        | RCode::YXDomain
        | RCode::YXRRSet
        | RCode::NXRRSet
        | RCode::NotImplemented
        | RCode::Refused
        | RCode::NotAuthoritative
        | RCode::NotZone
        | RCode::Unknown(_) => false,
    }
}

pub(crate) fn has_soa_for_question(reply: &Message, question: &Question) -> bool {
    let QClassType::Class(class) = question.qclass else {
        return false;
    };
    reply.authorities.iter().any(|record| {
        record.class == class
            && matches!(record.rdata, RData::SOA { .. })
            && question.qname.is_descendant_of(&record.name)
    })
}

pub(super) fn has_ns_for_question_class(reply: &Message, question: &Question) -> bool {
    let QClassType::Class(class) = question.qclass else {
        return false;
    };
    reply
        .authorities
        .iter()
        .any(|record| record.class == class && matches!(record.rdata, RData::NS(_)))
}

pub(crate) fn delegation_progresses(current: &DomainName, next: &DomainName) -> bool {
    next.as_ref().len() > current.as_ref().len() && next.is_descendant_of(current)
}

pub(crate) fn has_requested_answer(answers: &[ResourceRecord], question: &Question) -> bool {
    let class = match question.qclass {
        QClassType::Class(class) => class,
        QClassType::ANY => {
            return answers.iter().any(|record| {
                record.name.eq_dns(&question.qname)
                    && query_type_matches_record(question.qtype, record.rtype)
            });
        }
        QClassType::Unknown(_) => return false,
    };
    answers.iter().any(|record| {
        record.class == class
            && record.name.eq_dns(&question.qname)
            && query_type_matches_record(question.qtype, record.rtype)
    })
}

pub(crate) fn query_type_matches_record(qtype: QueryType, rtype: dns::RecordType) -> bool {
    match qtype {
        QueryType::ANY => true,
        QueryType::MAILB => matches!(
            rtype,
            dns::RecordType::MB | dns::RecordType::MG | dns::RecordType::MR
        ),
        QueryType::MAILA => matches!(rtype, dns::RecordType::MD | dns::RecordType::MF),
        _ => u16::from(rtype) == u16::from(qtype),
    }
}

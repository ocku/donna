use dns::{
    DomainName, Message, QClassType, QueryType, Question, RData, RecordType, ResourceRecord,
};

use crate::response::{CnameError, cname_restart, wildcard_proofs};

pub(super) struct CachedCname {
    pub(super) answers: Vec<ResourceRecord>,
    pub(super) authorities: Vec<ResourceRecord>,
    pub(super) target: DomainName,
    pub(super) authenticated: bool,
}

/// Consumes a selected positive CNAME entry, without selecting and cloning its
/// records a second time. Positive admission stores owner-local answers in
/// CNAME-then-signatures order, and retains only their wildcard authorities.
/// Unrecognized shapes use the ordinary parser on this same cache selection.
pub(super) fn cached_cname(
    reply: Message,
    question: &Question,
) -> Result<Option<CachedCname>, CnameError> {
    if matches!(question.qtype, QueryType::CNAME | QueryType::ANY) {
        // Preserve validation/error ordering even for callers that do not use
        // the resolver's ordinary non-CNAME/non-ANY traversal guard.
        return cname_restart(&reply.answers, question).map(|_| None);
    }
    if let Some(target) = simple_cname_target(&reply.answers, question) {
        return Ok(Some(CachedCname {
            target: target?,
            answers: reply.answers,
            authorities: reply.authorities,
            authenticated: reply.headers.ad,
        }));
    }
    let Some((answers, target)) = cname_restart(&reply.answers, question)? else {
        return Ok(None);
    };
    Ok(Some(CachedCname {
        authorities: wildcard_proofs(&reply, &answers),
        answers,
        target,
        authenticated: reply.headers.ad,
    }))
}

pub(super) fn simple_cname_target(
    answers: &[ResourceRecord],
    question: &Question,
) -> Option<Result<DomainName, CnameError>> {
    if matches!(question.qtype, QueryType::CNAME | QueryType::ANY) {
        return None;
    }
    if let QClassType::Class(class) = question.qclass
        && let Some(first) = answers.first()
        && first.rtype == RecordType::CNAME
        && first.class == class
        && first.name.eq_dns(&question.qname)
        && let RData::CNAME(target) = &first.rdata
        && answers[1..].iter().all(|record| {
            record.class == class
                && record.name.eq_dns(&question.qname)
                && record.rtype == RecordType::RRSIG
                && matches!(&record.rdata, RData::RRSIG(signature)
                    if signature.type_covered == u16::from(RecordType::CNAME))
        })
    {
        if target.eq_dns(&question.qname) {
            return Some(Err(CnameError::Loop));
        }
        return Some(Ok(target.clone()));
    }
    None
}

#[cfg(test)]
mod tests;

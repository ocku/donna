use dns::{Message, OpCode, QClassType, RCode};

pub(super) fn request_error(query: &Message) -> Option<RCode> {
    let is_axfr = query
        .questions
        .first()
        .is_some_and(|question| question.qtype == dns::QueryType::AXFR);
    // TC is meaningful only in responses. AXFR request flags have a separate
    // policy in `axfr_request_error` and intentionally remain unaffected.
    if query.headers.tc && !is_axfr {
        return Some(RCode::FormatError);
    }
    let error = request_error_without_axfr(query);
    if error.is_none() && is_axfr {
        return Some(RCode::NotImplemented);
    }
    error
}

fn request_error_without_axfr(query: &Message) -> Option<RCode> {
    if query.headers.qr || query.headers.aa || query.headers.ra || query.headers.rcode != RCode::Ok
    {
        return Some(RCode::FormatError);
    }
    if query
        .questions
        .iter()
        .any(|question| !question.is_wire_canonical())
        || contains_noncanonical_opt(query)
        || query.edns().is_err()
        || query
            .edns()
            .ok()
            .flatten()
            .is_some_and(|edns| edns.extended_rcode != 0 || edns.validate_options().is_err())
    {
        return Some(RCode::FormatError);
    }
    if query.headers.opcode != OpCode::Query {
        return Some(RCode::NotImplemented);
    }
    if query.questions.len() != 1 || !query.answers.is_empty() {
        return Some(RCode::FormatError);
    }
    if query.questions[0].qtype.value() == 251 {
        return Some(RCode::NotImplemented);
    }
    if !query.authorities.is_empty() {
        return Some(RCode::FormatError);
    }
    None
}

pub(super) fn axfr_request_error(query: &Message) -> Option<RCode> {
    if query.headers.qr || query.headers.rcode != RCode::Ok {
        return Some(RCode::FormatError);
    }
    if query
        .questions
        .iter()
        .any(|question| !question.is_wire_canonical())
        || contains_noncanonical_opt(query)
        || query.edns().is_err()
        || query
            .edns()
            .ok()
            .flatten()
            .is_some_and(|edns| edns.extended_rcode != 0 || edns.validate_options().is_err())
    {
        return Some(RCode::FormatError);
    }
    if query.headers.opcode != OpCode::Query {
        return Some(RCode::NotImplemented);
    }
    if query.questions.len() != 1 || !query.answers.is_empty() || !query.authorities.is_empty() {
        return Some(RCode::FormatError);
    }
    if query.questions[0].qclass == QClassType::ANY {
        return Some(RCode::FormatError);
    }
    None
}

fn contains_noncanonical_opt(query: &Message) -> bool {
    query
        .answers
        .iter()
        .chain(&query.authorities)
        .chain(&query.additionals)
        .any(|record| u16::from(record.rtype) == 41 && record.rtype != dns::RecordType::OPT)
}

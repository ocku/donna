//! Client-facing request checks and response correlation.
use super::*;
use dns::OpCode;

pub(super) fn correlate(response: &mut Message, request: &Message) {
    response.headers.id = request.headers.id;
    response.headers.aa = false;
    response.headers.rd = request.headers.rd;
    response.headers.ra = true;
    response.headers.cd = request.headers.cd;
    response.headers.ad &= !request.headers.cd
        && (request.headers.ad || request.edns().ok().flatten().is_some_and(|e| e.dnssec_ok));
    response.questions.clone_from(&request.questions);
}

pub(super) fn validate(request: &Message) -> Option<Message> {
    if request.headers.qr
        || request.headers.aa
        || request.headers.tc
        || request.headers.ra
        || request.headers.rcode != RCode::Ok
        || request.questions.len() != 1
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || !request.questions.iter().all(|q| q.is_wire_canonical())
    {
        return Some(request.error_response(RCode::FormatError, true));
    }
    if let Some(response) = request.edns_error_response(true) {
        return Some(response);
    }
    if request.headers.opcode != OpCode::Query
        || request
            .additionals
            .iter()
            .any(|r| r.rtype != RecordType::OPT)
        || matches!(
            request.questions[0].qtype,
            dns::QueryType::AXFR | dns::QueryType::IXFR
        )
    {
        return Some(request.error_response(RCode::NotImplemented, true));
    }
    if !request.headers.rd {
        return Some(request.error_response(RCode::Refused, true));
    }
    None
}

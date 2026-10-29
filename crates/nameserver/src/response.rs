use dns::{Edns, ExtendedDnsError, ExtendedDnsErrorCode, Headers, Message, RCode, RecordType};

pub(super) fn base_response(query: &Message) -> Message {
    Message {
        headers: Headers {
            id: query.headers.id,
            qr: true,
            opcode: query.headers.opcode,
            rd: query.headers.rd,
            ..Headers::default()
        },
        questions: if query.questions.iter().all(dns::Question::is_wire_canonical) {
            query.questions.clone()
        } else {
            Vec::new()
        },
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: query
            .answers
            .iter()
            .chain(&query.authorities)
            .chain(&query.additionals)
            .any(|record| record.rtype == RecordType::OPT)
            .then(|| response_edns(query).into_record())
            .into_iter()
            .collect(),
    }
}

pub(super) fn bad_version_response(query: &Message) -> Message {
    let mut reply = base_response(query);
    if let Some(record) = reply
        .additionals
        .iter_mut()
        .find(|record| record.rtype == RecordType::OPT)
    {
        *record = Edns {
            // BADVERS is extended RCODE 16: upper eight bits 1, header bits 0.
            extended_rcode: 1,
            ..response_edns(query)
        }
        .into_record();
    }
    reply
}

fn response_edns(query: &Message) -> Edns {
    Edns {
        // RFC 3225 section 3 and RFC 6840 section 5.6 require a responder to
        // copy the request's DO bit. Other request flags and options are not
        // echoed by generic response construction.
        dnssec_ok: query
            .edns()
            .ok()
            .flatten()
            .is_some_and(|edns| edns.dnssec_ok),
        ..Edns::default()
    }
}

pub(super) fn error_response(query: &Message, code: RCode) -> Message {
    let mut reply = base_response(query);
    reply.headers.rcode = code;
    reply
}

pub(super) fn annotate_extended_error(reply: &mut Message, code: ExtendedDnsErrorCode) {
    let Some(record) = reply
        .additionals
        .iter_mut()
        .find(|record| record.rtype == RecordType::OPT)
    else {
        return;
    };
    let Ok(mut edns) = Edns::try_from_record(record) else {
        return;
    };
    edns.push_extended_dns_error(ExtendedDnsError::without_text(code))
        .expect("named EDE codes are canonical");
    *record = edns.into_record();
}

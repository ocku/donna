use dns::{ClassType, DomainName, Edns, EdnsOption, Headers, QClassType, QueryType, Question};

use super::{Message, edns_fallback_allowed, signals_edns_unawareness};

fn request() -> Message {
    crate::protocol::query(
        7,
        &Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        },
        1232,
    )
}

#[test]
fn fallback_requires_payload_only_edns_and_an_unextended_formerr() {
    let request = request();
    assert!(edns_fallback_allowed(&request));

    let mut dnssec_request = request.clone();
    dnssec_request.additionals[0] = Edns {
        dnssec_ok: true,
        ..Edns::new(1232)
    }
    .into_record();
    assert!(!edns_fallback_allowed(&dnssec_request));

    let mut option_request = request.clone();
    option_request.additionals[0] = Edns {
        options: vec![EdnsOption {
            code: 65_001,
            data: vec![1],
        }],
        ..Edns::new(1232)
    }
    .into_record();
    assert!(!edns_fallback_allowed(&option_request));

    let mut formerr = Message {
        headers: Headers {
            id: 7,
            qr: true,
            rcode: dns::RCode::FormatError,
            ..Headers::default()
        },
        questions: request.questions.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    assert!(signals_edns_unawareness(&formerr));
    formerr.additionals.push(Edns::new(1232).into_record());
    assert!(!signals_edns_unawareness(&formerr));
}

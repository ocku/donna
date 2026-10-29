mod indexed;

use std::net::Ipv4Addr;

use dns::{
    Caa, ClassType, DomainName, Edns, FromWire, Headers, IntoWire, Message, QClassType, QueryType,
    Question, RData, RecordType, ResourceRecord,
};

use super::normalize_response_rrsets;

fn question() -> Question {
    Question {
        qname: DomainName::from_labels(vec![b"www".to_vec(), b"example".to_vec()]).unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn address(question: &Question, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    }
}

#[test]
fn suppresses_duplicate_records_after_authoritative_ttl_normalization() {
    let question = question();
    let mut reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: vec![address(&question, 60), address(&question, 30)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    assert!(normalize_response_rrsets(&mut reply, &question));
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].ttl, 30);
}

#[test]
fn suppresses_case_insensitive_duplicates_but_preserves_distinct_records() {
    let question = question();
    let mut duplicate = address(&question, 60);
    duplicate.name = DomainName::from_labels(vec![b"WWW".to_vec(), b"EXAMPLE".to_vec()]).unwrap();
    let mut distinct = address(&question, 60);
    distinct.rdata = RData::A(Ipv4Addr::new(192, 0, 2, 2));
    let mut reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: vec![address(&question, 60), distinct, duplicate],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    assert!(normalize_response_rrsets(&mut reply, &question));
    assert_eq!(reply.answers.len(), 2);
}

#[test]
fn preserves_reserved_caa_flags_at_the_receive_boundary() {
    let mut caa_question = question();
    caa_question.qtype = QueryType::CAA;
    let mut reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![caa_question.clone()],
        answers: vec![ResourceRecord {
            name: caa_question.qname.clone(),
            rtype: RecordType::CAA,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CAA(Caa {
                flags: Caa::ISSUER_CRITICAL_FLAG | 0x01,
                tag: b"future".to_vec(),
                value: b"opaque".to_vec(),
            }),
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    assert!(normalize_response_rrsets(&mut reply, &caa_question));
    assert!(matches!(
        &reply.answers[0].rdata,
        RData::CAA(caa)
            if caa.flags == Caa::ISSUER_CRITICAL_FLAG | 0x01 && caa.has_reserved_flags()
    ));
    assert!(reply.answers[0].validate().is_ok());
    let forwarded = Message::from_wire(&reply.into_wire().unwrap()).unwrap();
    assert!(matches!(
        &forwarded.answers[0].rdata,
        RData::CAA(caa) if caa.flags == 0x81
    ));
}

#[test]
fn accepts_and_preserves_future_edns_flags_during_upstream_normalization() {
    let question = question();
    let mut opt = Edns::new(1232).into_record();
    opt.ttl |= 0x0123;
    let mut reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: vec![address(&question, 60)],
        authorities: Vec::new(),
        additionals: vec![opt],
    };

    assert!(normalize_response_rrsets(&mut reply, &question));
    assert_eq!(reply.edns().unwrap().unwrap().z, 0x0123);
}

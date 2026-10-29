use super::*;

#[test]
fn round_trips_a_compressed_response() {
    let owner = name(&[b"www", b"example", b"com"]);
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            id: 0x1234,
            ..Headers::default()
        })
        .questions(vec![Question {
            qname: owner.clone(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .answers(vec![ResourceRecord {
            name: owner,
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }])
        .authorities(vec![])
        .additionals(vec![])
        .build()
        .unwrap();
    let bytes = message.into_wire().unwrap();
    assert!(bytes.windows(2).any(|pair| pair[0] & 0xc0 == 0xc0));
    let decoded = Message::from_wire(&bytes).unwrap();
    assert_eq!(decoded.answers.len(), 1);
    assert_eq!(
        decoded.questions[0].qname.as_ref(),
        message.questions[0].qname.as_ref()
    );
}

/// RFC 1035 §4.1.2: the question section holds QDCOUNT entries, which may
/// exceed one even though most messages carry a single question.
#[test]
fn round_trips_a_message_with_multiple_questions() {
    let qname = name(&[b"www", b"example", b"com"]);
    let questions = [
        Question {
            qname: qname.clone(),
            qtype: QueryType::MX,
            qclass: QClassType::Class(ClassType::IN),
        },
        Question {
            qname,
            qtype: QueryType::TXT,
            qclass: QClassType::ANY,
        },
    ];
    let message = Message::builder().questions(questions).build().unwrap();

    let decoded = Message::from_wire(&message.into_wire().unwrap()).unwrap();
    assert_eq!(decoded.questions.len(), 2);
    assert_eq!(decoded.questions[0].qtype, QueryType::MX);
    assert_eq!(decoded.questions[1].qtype, QueryType::TXT);
    assert_eq!(decoded.questions[1].qclass, QClassType::ANY);
}

#[test]
fn round_trips_every_supported_rdata_format() {
    let owner = |label: &'static [u8]| name(&[label, b"example", b"com"]);
    let records = vec![
        ResourceRecord {
            name: owner(b"a"),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        },
        ResourceRecord {
            name: owner(b"aaaa"),
            rtype: RecordType::AAAA,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        },
        ResourceRecord {
            name: owner(b"cname"),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::CNAME(name(&[b"canonical", b"example", b"com"])),
        },
        ResourceRecord {
            name: owner(b"hinfo"),
            rtype: RecordType::HINFO,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::HINFO {
                cpu: b"x86_64".to_vec(),
                os: b"unix".to_vec(),
            },
        },
        ResourceRecord {
            name: owner(b"mx"),
            rtype: RecordType::MX,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::MX {
                preference: 10,
                exchange: name(&[b"mail", b"example", b"com"]),
            },
        },
        ResourceRecord {
            name: owner(b"srv"),
            rtype: RecordType::SRV,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::SRV {
                priority: 10,
                weight: 20,
                port: 443,
                target: name(&[b"service", b"example", b"com"]),
            },
        },
        ResourceRecord {
            name: owner(b"ns-owner"),
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::NS(name(&[b"ns", b"example", b"com"])),
        },
        ResourceRecord {
            name: owner(b"ptr"),
            rtype: RecordType::PTR,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::PTR(name(&[b"host", b"example", b"com"])),
        },
        ResourceRecord {
            name: owner(b"soa"),
            rtype: RecordType::SOA,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::SOA {
                mname: name(&[b"ns", b"example", b"com"]),
                rname: name(&[b"hostmaster", b"example", b"com"]),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            },
        },
        ResourceRecord {
            name: owner(b"md"),
            rtype: RecordType::MD,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::MD(name(&[b"mail", b"example", b"com"])),
        },
        ResourceRecord {
            name: owner(b"mf"),
            rtype: RecordType::MF,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::MF(name(&[b"forwarder", b"example", b"com"])),
        },
        ResourceRecord {
            name: owner(b"mb"),
            rtype: RecordType::MB,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::MB(name(&[b"mailbox", b"example", b"com"])),
        },
        ResourceRecord {
            name: owner(b"mg"),
            rtype: RecordType::MG,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::MG(name(&[b"member", b"example", b"com"])),
        },
        ResourceRecord {
            name: owner(b"mr"),
            rtype: RecordType::MR,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::MR(name(&[b"renamed", b"example", b"com"])),
        },
        ResourceRecord {
            name: owner(b"minfo"),
            rtype: RecordType::MINFO,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::MINFO {
                rmailbx: name(&[b"requests", b"example", b"com"]),
                emailbx: name(&[b"errors", b"example", b"com"]),
            },
        },
        ResourceRecord {
            name: owner(b"null"),
            rtype: RecordType::NULL,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::NULL(vec![0, 0xff, 0x42]),
        },
        ResourceRecord {
            name: owner(b"wks"),
            rtype: RecordType::WKS,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::WKS {
                address: Ipv4Addr::new(192, 0, 2, 2),
                protocol: 6,
                bitmap: vec![0, 0x80],
            },
        },
        ResourceRecord {
            name: owner(b"txt"),
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 1,
            rdata: RData::TXT(vec![b"first".to_vec(), Vec::new(), b"third".to_vec()]),
        },
    ];
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .questions(vec![])
        .answers(records)
        .authorities(vec![])
        .additionals(vec![])
        .build_unchecked();
    assert_eq!(
        message.into_wire(),
        super::super::encode_message_context_with_record_checks(&message, None, true)
    );
    let decoded = Message::from_wire(&message.into_wire().unwrap()).unwrap();
    assert_eq!(decoded.answers.len(), 18);
    for (decoded, expected) in decoded.answers.iter().zip(&message.answers) {
        assert_eq!(decoded.rtype, expected.rtype);
        assert_eq!(decoded.rdata, expected.rdata);
    }
}

#[test]
fn decodes_malformed_rrsets_but_rejects_reencoding_them() {
    let mut wire = vec![
        0, 0, // ID
        0x80, 0, // response
        0, 0, // QDCOUNT
        0, 2, // ANCOUNT
        0, 0, 0, 0, // NSCOUNT / ARCOUNT
    ];
    for (ttl, address) in [(60_u32, [192, 0, 2, 1]), (30, [192, 0, 2, 2])] {
        wire.extend_from_slice(&[0, 0, 1, 0, 1]); // root owner, TYPE A, CLASS IN
        wire.extend_from_slice(&ttl.to_be_bytes());
        wire.extend_from_slice(&[0, 4]);
        wire.extend_from_slice(&address);
    }

    let decoded = Message::from_wire(&wire).unwrap();
    assert_eq!(decoded.answers.len(), 2);
    assert!(matches!(
        decoded.validate_strict(),
        Err(MessageValidationError::InvalidRecord {
            error: crate::RecordValidationError::InconsistentTtl { .. },
            ..
        })
    ));
    assert!(decoded.into_wire().is_err());
}

/// RFC 1035 §4.1.4 permits a pointer to "a prior occurance" of any
/// name-suffix labels, including labels inside an earlier record's RDATA.
/// Regression test: the decoder must register every direct label boundary
/// as a valid pointer target, even within RDATA.
#[test]
fn decodes_a_pointer_into_an_earlier_records_rdata_name_suffix() {
    let mut wire = vec![
        0, 0, // ID
        0x80, 0, // response
        0, 0, // QDCOUNT
        0, 2, // ANCOUNT
        0, 0, 0, 0, // NSCOUNT / ARCOUNT
    ];
    // RR 1: a.example.com NS ns.example.com — "example" starts at offset 14.
    wire.extend_from_slice(&[
        1, b'a', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
        0, // a.example.com
        0, 2, // NS
        0, 1, // IN
        0, 0, 0, 0, // TTL
        0, 16, // RDLENGTH
        2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    assert_eq!(wire.len(), 53);
    // RR 2: b.example.com PTR example.com, written as a pointer to the
    // "example" suffix of RR 1's owner name.
    wire.extend_from_slice(&[
        1, b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
        0, // b.example.com
        0, 12, // PTR
        0, 1, // IN
        0, 0, 0, 0, // TTL
        0, 2, // RDLENGTH
        0xc0, 14, // pointer to "example.com" inside RR 1's owner
    ]);

    let message = Message::from_wire(&wire).unwrap();
    assert!(matches!(
        &message.answers[1].rdata,
        RData::PTR(name) if name.as_ref() == [b"example".to_vec(), b"com".to_vec()]
    ));
}

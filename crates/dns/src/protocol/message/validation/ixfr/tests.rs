use crate::*;

fn fixture() -> (Message, Question) {
    let question = Question {
        qname: DomainName::from_dotted("example.").unwrap(),
        qtype: QueryType::IXFR,
        qclass: QClassType::Class(ClassType::IN),
    };
    let soa = |serial| ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::SOA {
            mname: DomainName::root(),
            rname: DomainName::root(),
            serial,
            refresh: 60,
            retry: 60,
            expire: 600,
            minimum: 60,
        },
    };
    let a = ResourceRecord {
        name: DomainName::from_dotted("host.example.").unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A("192.0.2.1".parse().unwrap()),
    };
    let mut changed = a.clone();
    changed.ttl = 120;
    let cname = ResourceRecord {
        rtype: RecordType::CNAME,
        rdata: RData::CNAME(DomainName::from_dotted("target.example.").unwrap()),
        ..a.clone()
    };
    let message = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: vec![
            soa(3),
            soa(1),
            a.clone(),
            soa(2),
            changed.clone(),
            soa(2),
            changed,
            soa(3),
            cname,
            a,
            soa(3),
        ],
        authorities: vec![],
        additionals: vec![],
    };
    (message, question)
}

#[test]
fn ixfr_operations_allow_repeated_records_and_version_changes() {
    let (mut message, question) = fixture();
    // A CNAME and A together in the same addition operation remain invalid.
    assert!(message.validate_strict().is_err());
    message.answers.remove(9);
    assert!(message.validate_strict().is_ok());
    assert!(message.into_wire().is_ok());
    message.questions.clear();
    assert!(message.into_wire().is_err());
    let wire = message.into_wire_ixfr(&question).unwrap();
    assert!(Message::from_wire(&wire).unwrap().questions.is_empty());
    let mut ordinary = question.clone();
    ordinary.qtype = QueryType::A;
    assert!(message.into_wire_ixfr(&ordinary).is_err());
    message.questions.push(ordinary);
    assert!(message.validate_strict().is_err());
}

#[test]
fn questionless_ixfr_tsig_stream_preserves_authenticated_bytes() {
    let (mut message, question) = fixture();
    message.answers.remove(9);
    let key = TsigKey::new(
        DomainName::from_dotted("key.example.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![7; 32],
    )
    .unwrap();
    let request_mac = vec![8; 32];
    let mut signer = TsigStreamSigner::new(key.clone(), request_mac.clone());
    let mut verifier = TsigStreamVerifier::new(key, request_mac);
    signer
        .sign_next_ixfr(&mut message, &question, 0, 100, 300, None)
        .unwrap();
    verifier
        .verify_next(&message.into_wire_ixfr(&question).unwrap(), 100, false)
        .unwrap();
    message.additionals.clear();
    message.questions.clear();
    signer
        .sign_next_ixfr(&mut message, &question, 0, 101, 300, None)
        .unwrap();
    let wire = message.into_wire_ixfr(&question).unwrap();
    verifier.verify_next(&wire, 101, true).unwrap();
    assert!(Message::from_wire(&wire).unwrap().questions.is_empty());
}

#[test]
fn questionless_ixfr_sig0_preserves_authenticated_bytes() {
    let (mut message, question) = fixture();
    message.answers.remove(9);
    message.questions.clear();
    let random = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let key = Sig0SigningKey::from_ed25519_pkcs8(
        DomainName::from_dotted("key.example.").unwrap(),
        0,
        3,
        pkcs8.as_ref(),
    )
    .unwrap();
    let request_wire = vec![0; 12];
    key.sign_response_ixfr(&mut message, &question, &request_wire, 100, 200)
        .unwrap();
    let wire = message.into_wire_ixfr(&question).unwrap();
    key.verification_key()
        .verify_response(&wire, &request_wire, 150)
        .unwrap();
    assert!(Message::from_wire(&wire).unwrap().questions.is_empty());
}

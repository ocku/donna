use super::wire::{stream_mac_input, tsig_record};
use super::*;
use crate::{
    ClassType, DomainName, Headers, IntoWire, Message, OpCode, QClassType, QueryType, Question,
    RCode, RecordType, Tsig, TsigAlgorithm, TsigErrorCode,
};

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn request(id: u16) -> Message {
    Message {
        headers: Headers {
            id,
            rd: true,
            ..Headers::default()
        },
        questions: vec![Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn response(id: u16, question: Question) -> Message {
    Message {
        headers: Headers {
            id,
            qr: true,
            rd: true,
            ..Headers::default()
        },
        questions: vec![question],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

#[test]
fn sha256_request_signing_verifies_exact_wire_and_removes_tsig() {
    let key = TsigKey::new(
        name(&["Key", "Example"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let mut message = request(0x1234);
    let mac = key
        .sign_request(&mut message, 1_700_000_000, 300, None)
        .unwrap();
    assert_eq!(
        mac,
        [
            0xec, 0xca, 0x30, 0x9b, 0xf2, 0xdd, 0x2f, 0xb0, 0x40, 0x0c, 0x80, 0xae, 0x74, 0x6a,
            0x59, 0xc0, 0x45, 0xbb, 0xd6, 0x3d, 0xc9, 0x89, 0x0c, 0x52, 0x05, 0x53, 0x6b, 0xc6,
            0x51, 0x6e, 0x71, 0x98,
        ]
    );
    assert_eq!(message.additionals.len(), 1);
    assert_eq!(message.additionals[0].rtype, RecordType::TSIG);

    let wire = message.into_wire().unwrap();
    let verified = key.verify_request(&wire, 1_700_000_250).unwrap();
    assert_eq!(verified.mac, mac);
    assert!(verified.message.additionals.is_empty());
    assert_eq!(verified.message.headers.id, 0x1234);
}

#[test]
fn sha1_supports_the_recommended_96_bit_truncation() {
    let key = TsigKey::new(
        name(&["key", "example"]),
        TsigAlgorithm::HmacSha1,
        b"twenty-octet-secret!".to_vec(),
    )
    .unwrap();
    let mut message = request(7);
    let mac = key
        .sign_request(&mut message, 1_700_000_000, 300, Some(12))
        .unwrap();
    assert_eq!(mac.len(), 12);
    key.verify_request(&message.into_wire().unwrap(), 1_700_000_000)
        .unwrap();
    assert!(matches!(
        key.sign_request(&mut request(8), 1_700_000_000, 300, Some(9)),
        Err(TsigAuthenticationError::InvalidMacLength { .. })
    ));
}

#[test]
fn detects_message_mac_key_algorithm_and_time_failures() {
    let key = TsigKey::new(
        name(&["key", "example"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let mut message = request(9);
    key.sign_request(&mut message, 1_700_000_000, 30, None)
        .unwrap();
    let wire = message.into_wire().unwrap();
    assert_eq!(
        key.verify_request(&wire, 1_700_000_031).unwrap_err(),
        TsigAuthenticationError::BadTime
    );
    assert!(matches!(
        key.authenticate_request(&wire, 1_700_000_031).unwrap(),
        TsigRequestAuthentication::BadTime(message) if message.mac.len() == 32
    ));

    let mut tampered = wire.clone();
    let www = tampered
        .windows(3)
        .position(|window| window == b"www")
        .unwrap();
    tampered[www] = b'x';
    assert_eq!(
        key.verify_request(&tampered, 1_700_000_000).unwrap_err(),
        TsigAuthenticationError::BadSignature
    );

    let other_key = TsigKey::new(
        name(&["other", "example"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    assert_eq!(
        other_key.verify_request(&wire, 1_700_000_000).unwrap_err(),
        TsigAuthenticationError::BadKey
    );
    let other_algorithm = TsigKey::new(
        name(&["key", "example"]),
        TsigAlgorithm::HmacSha1,
        b"0123456789abcdef0123".to_vec(),
    )
    .unwrap();
    assert_eq!(
        other_algorithm
            .verify_request(&wire, 1_700_000_000)
            .unwrap_err(),
        TsigAuthenticationError::BadAlgorithm
    );
}

#[test]
fn response_mac_is_chained_to_the_validated_request_mac() {
    let key = TsigKey::new(
        name(&["key", "example"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let mut query = request(10);
    let request_mac = key
        .sign_request(&mut query, 1_700_000_000, 300, Some(16))
        .unwrap();
    let mut answer = response(10, query.questions[0].clone());
    let response_mac = key
        .sign_response(
            &mut answer,
            &request_mac,
            10,
            1_700_000_001,
            300,
            TsigErrorCode::NoError,
            Vec::new(),
            Some(16),
        )
        .unwrap();
    let verified = key
        .verify_response(&answer.into_wire().unwrap(), &request_mac, 1_700_000_001)
        .unwrap();
    assert_eq!(verified.mac, response_mac);

    let mut wrong_request_mac = request_mac;
    wrong_request_mac[0] ^= 1;
    assert_eq!(
        key.verify_response(
            &answer.into_wire().unwrap(),
            &wrong_request_mac,
            1_700_000_001
        )
        .unwrap_err(),
        TsigAuthenticationError::BadSignature
    );
}

#[test]
fn badtime_response_carries_and_authenticates_server_time() {
    let key = TsigKey::new(
        name(&["key"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let mut answer = response(11, request(11).questions.remove(0));
    answer.headers.rcode = RCode::NotAuthoritative;
    let request_mac = vec![0xa5; 32];
    let server_time = 1_700_100_000_u64;
    key.sign_response(
        &mut answer,
        &request_mac,
        11,
        1_700_000_000,
        300,
        TsigErrorCode::BadTime,
        server_time.to_be_bytes()[2..].to_vec(),
        None,
    )
    .unwrap();
    let verified = key
        .verify_response(&answer.into_wire().unwrap(), &request_mac, 1_700_000_000)
        .unwrap();
    assert_eq!(verified.tsig.bad_time_server_time(), Some(server_time));
}

#[test]
fn signed_update_response_may_omit_copied_sections() {
    let key = TsigKey::new(
        name(&["key"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let mut answer = Message {
        headers: Headers {
            id: 14,
            qr: true,
            opcode: OpCode::Update,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let request_mac = vec![0xa5; 32];
    key.sign_response(
        &mut answer,
        &request_mac,
        14,
        1_700_000_000,
        300,
        TsigErrorCode::NoError,
        Vec::new(),
        None,
    )
    .unwrap();

    let wire = answer.into_wire().unwrap();
    let verified = key
        .verify_response(&wire, &request_mac, 1_700_000_000)
        .unwrap();
    assert!(verified.message.questions.is_empty());
    assert!(verified.message.additionals.is_empty());
}

#[test]
fn stream_signer_and_verifier_chain_every_generated_message() {
    let key = TsigKey::new(
        name(&["transfer", "key"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let request_mac = vec![0x5a; 32];
    let question = request(12).questions.remove(0);
    let mut first = response(12, question.clone());
    let mut last = response(12, question);
    let mut signer = TsigStreamSigner::new(key.clone(), request_mac.clone());
    signer
        .sign_next(&mut first, 12, 1_700_000_000, 300, None)
        .unwrap();
    signer
        .sign_next(&mut last, 12, 1_700_000_001, 300, None)
        .unwrap();

    let mut verifier = TsigStreamVerifier::new(key, request_mac);
    let first_batch = verifier
        .verify_next(&first.into_wire().unwrap(), 1_700_000_000, false)
        .unwrap()
        .unwrap();
    assert_eq!(first_batch.messages.len(), 1);
    let last_batch = verifier
        .verify_next(&last.into_wire().unwrap(), 1_700_000_001, true)
        .unwrap()
        .unwrap();
    assert_eq!(last_batch.messages.len(), 1);
}

#[test]
fn stream_verifier_withholds_unsigned_intermediates_until_the_next_mac() {
    let key = TsigKey::new(
        name(&["transfer", "key"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let request_mac = vec![0x5a; 32];
    let question = request(13).questions.remove(0);
    let mut first = response(13, question.clone());
    let mut signer = TsigStreamSigner::new(key.clone(), request_mac.clone());
    let prior_mac = signer
        .sign_next(&mut first, 13, 1_700_000_000, 300, None)
        .unwrap();

    let middle = response(13, question.clone());
    let middle_wire = middle.into_wire().unwrap();
    let mut last = response(13, question);
    let mut current_unsigned = last.into_wire().unwrap();
    current_unsigned[..2].copy_from_slice(&13_u16.to_be_bytes());
    let mut tsig = Tsig {
        algorithm: key.algorithm.name(),
        time_signed: 1_700_000_002,
        fudge: 300,
        mac: Vec::new(),
        original_id: 13,
        error: TsigErrorCode::NoError,
        other_data: Vec::new(),
    };
    let input = stream_mac_input(&prior_mac, &middle_wire, &current_unsigned, &tsig);
    tsig.mac = key.calculate(&input);
    last.additionals.push(tsig_record(key.name.clone(), tsig));

    let mut verifier = TsigStreamVerifier::new(key, request_mac);
    verifier
        .verify_next(&first.into_wire().unwrap(), 1_700_000_000, false)
        .unwrap()
        .unwrap();
    assert!(
        verifier
            .verify_next(&middle_wire, 1_700_000_001, false)
            .unwrap()
            .is_none()
    );
    let batch = verifier
        .verify_next(&last.into_wire().unwrap(), 1_700_000_002, true)
        .unwrap()
        .unwrap();
    assert_eq!(batch.messages.len(), 2);
    assert!(
        batch
            .messages
            .iter()
            .all(|message| message.additionals.is_empty())
    );
}

#[test]
fn stream_verifier_rejects_a_decreasing_time_signed() {
    let key = TsigKey::new(
        name(&["transfer", "key"]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let request_mac = vec![0x5a; 32];
    let question = request(15).questions.remove(0);
    let mut first = response(15, question.clone());
    let mut second = response(15, question);
    let mut signer = TsigStreamSigner::new(key.clone(), request_mac.clone());
    signer
        .sign_next(&mut first, 15, 1_700_000_010, 300, None)
        .unwrap();
    signer
        .sign_next(&mut second, 15, 1_700_000_009, 300, None)
        .unwrap();

    let mut verifier = TsigStreamVerifier::new(key, request_mac);
    verifier
        .verify_next(&first.into_wire().unwrap(), 1_700_000_010, false)
        .unwrap();
    assert_eq!(
        verifier
            .verify_next(&second.into_wire().unwrap(), 1_700_000_010, true)
            .unwrap_err(),
        TsigAuthenticationError::TimeRegression {
            previous: 1_700_000_010,
            current: 1_700_000_009,
        }
    );
}

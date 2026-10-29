use ring::rand::SystemRandom;

use super::*;
use crate::{Headers, QClassType, QueryType, Question};

fn signing_key() -> Sig0SigningKey {
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Sig0SigningKey::from_ed25519_pkcs8(
        DomainName::from_dotted("host.example.").unwrap(),
        0,
        3,
        pkcs8.as_ref(),
    )
    .unwrap()
}

fn request() -> Message {
    Message::builder()
        .headers(Headers {
            id: 0x1234,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted("example.").unwrap(),
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

#[test]
fn signs_and_verifies_exact_request_wire() {
    let key = signing_key();
    let mut request = request();
    key.sign_request(&mut request, 100, 200).unwrap();
    let wire = request.into_wire().unwrap();

    let verified = key.verification_key().verify_request(&wire, 150).unwrap();
    assert_eq!(verified.message.questions.len(), 1);
    assert!(verified.message.additionals.is_empty());
    assert!(verified.sig.is_sig0());

    let mut altered = wire.clone();
    altered[1] ^= 1;
    assert!(matches!(
        key.verification_key().verify_request(&altered, 150),
        Err(Sig0Error::BadSignature)
    ));
    assert!(matches!(
        key.verification_key().verify_request(&wire, 201),
        Err(Sig0Error::BadTime)
    ));

    let mut noncanonical = request;
    let record = noncanonical.additionals.last_mut().unwrap();
    record.name = DomainName::from_dotted("ignored.example.").unwrap();
    record.class = ClassType::IN;
    record.ttl = 123;
    key.verification_key()
        .verify_request(&noncanonical.into_wire().unwrap(), 150)
        .unwrap();
}

#[test]
fn response_signature_is_bound_to_full_query_wire() {
    let key = signing_key();
    let mut request = request();
    key.sign_request(&mut request, 100, 200).unwrap();
    let request_wire = request.into_wire().unwrap();

    let mut response = Message::builder()
        .headers(Headers {
            id: 0x1234,
            qr: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted("example.").unwrap(),
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    key.sign_response(&mut response, &request_wire, 100, 200)
        .unwrap();
    let response_wire = response.into_wire().unwrap();

    key.verification_key()
        .verify_response(&response_wire, &request_wire, 150)
        .unwrap();
    let mut different_query = request_wire.clone();
    different_query[1] ^= 1;
    assert!(matches!(
        key.verification_key()
            .verify_response(&response_wire, &different_query, 150),
        Err(Sig0Error::BadSignature)
    ));
}

#[test]
fn rejects_sig0_and_tsig_coexistence() {
    let key = signing_key();
    let mut request = request();
    let tsig = crate::TsigKey::new(
        DomainName::from_dotted("shared.example.").unwrap(),
        crate::TsigAlgorithm::HmacSha256,
        b"secret".to_vec(),
    )
    .unwrap();
    tsig.sign_request(&mut request, 150, 300, None).unwrap();
    assert!(matches!(
        key.sign_request(&mut request, 100, 200),
        Err(Sig0Error::AlreadySigned)
    ));
}

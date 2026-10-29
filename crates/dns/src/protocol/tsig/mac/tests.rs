use super::*;
use crate::{
    ClassType, DomainName, Headers, IntoWire, Message, QClassType, QueryType, Question, RData,
    TsigAuthenticationError, TsigKey,
};

fn legacy(algorithm: TsigAlgorithm, key: &[u8], input: &[u8]) -> Vec<u8> {
    let algorithm = match algorithm {
        TsigAlgorithm::HmacSha1 => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        TsigAlgorithm::HmacSha256 => ring::hmac::HMAC_SHA256,
    };
    ring::hmac::sign(&ring::hmac::Key::new(algorithm, key), input)
        .as_ref()
        .to_vec()
}

#[test]
fn rustcrypto_matches_independent_ring_for_key_blocks_and_every_tag_prefix() {
    for algorithm in [TsigAlgorithm::HmacSha1, TsigAlgorithm::HmacSha256] {
        for key_len in [0, 1, 16, 20, 32, 63, 64, 65, 127, 128, 129, 1024] {
            let key: Vec<_> = (0..key_len).map(|i| (i * 17 + 3) as u8).collect();
            for length in [0, 1, 55, 56, 63, 64, 65, 255, 512, 1232, 65535] {
                let input: Vec<_> = (0..length).map(|i| (i * 131 + 7) as u8).collect();
                let old = legacy(algorithm, &key, &input);
                assert_eq!(calculate(algorithm, &key, &input), old);
                for n in 1..=old.len() {
                    assert!(verify(algorithm, &key, &input, &old[..n]));
                    let mut bad = old[..n].to_vec();
                    bad[n - 1] ^= 1;
                    assert!(!verify(algorithm, &key, &input, &bad));
                }
                assert!(!verify(algorithm, &key, &input, &[]));
                let mut excess = old;
                excess.push(0);
                assert!(!verify(algorithm, &key, &input, &excess));
            }
        }
    }
}

fn request() -> Message {
    Message {
        headers: Headers {
            id: 17,
            ..Headers::default()
        },
        questions: vec![Question {
            qname: DomainName::from_dotted("example.test.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
}

#[test]
fn protocol_lengths_and_badtrunc_vs_badsig_policy_remain_separate() {
    for algorithm in [TsigAlgorithm::HmacSha1, TsigAlgorithm::HmacSha256] {
        let key = TsigKey::new(
            DomainName::from_dotted("key.test.").unwrap(),
            algorithm,
            vec![7; 65],
        )
        .unwrap();
        let strict = key
            .clone()
            .with_minimum_mac_len(algorithm.output_len())
            .unwrap();
        let mut signed = request();
        let tag = key.sign_request(&mut signed, 100, 30, None).unwrap();
        let split = super::super::wire::split_tsig(&signed.into_wire().unwrap()).unwrap();
        let input =
            super::super::wire::standard_mac_input(None, &split.unsigned_wire, &split.record);
        assert_eq!(tag, legacy(algorithm, &[7; 65], &input));
        for length in 0..=algorithm.output_len() + 1 {
            let mut message = signed.clone();
            let RData::TSIG(tsig) = &mut message.additionals.last_mut().unwrap().rdata else {
                unreachable!()
            };
            tsig.mac.resize(length, 0);
            let wire = message.into_wire().unwrap();
            let minimum = algorithm.protocol_minimum_mac_len();
            if !(minimum..=algorithm.output_len()).contains(&length) {
                assert!(matches!(
                    key.verify_request(&wire, 100),
                    Err(TsigAuthenticationError::InvalidMacLength { .. })
                ));
                continue;
            }
            key.verify_request(&wire, 100).unwrap();
            if length < algorithm.output_len() {
                assert!(matches!(
                    strict.verify_request(&wire, 100),
                    Err(TsigAuthenticationError::BadTruncation { .. })
                ));
            } else {
                strict.verify_request(&wire, 100).unwrap();
            }
            let RData::TSIG(tsig) = &mut message.additionals.last_mut().unwrap().rdata else {
                unreachable!()
            };
            tsig.mac[length - 1] ^= 1;
            assert!(matches!(
                strict.verify_request(&message.into_wire().unwrap(), 100),
                Err(TsigAuthenticationError::BadSignature)
            ));
        }
    }
}

#[test]
fn unsigned_stream_batches_verify_ring_generated_running_macs() {
    use super::super::wire::{split_tsig, standard_mac_input, stream_mac_input, tsig_record};
    use crate::{Tsig, TsigErrorCode, TsigStreamVerifier};

    for algorithm in [TsigAlgorithm::HmacSha1, TsigAlgorithm::HmacSha256] {
        let secret = vec![19; 129];
        let owner = DomainName::from_dotted("stream.key.").unwrap();
        let key = TsigKey::new(owner.clone(), algorithm, secret.clone()).unwrap();
        for length in algorithm.protocol_minimum_mac_len()..=algorithm.output_len() {
            let request_mac = vec![0x55; length];
            let mut first = request();
            first.headers.qr = true;
            let prior = key
                .sign_response(
                    &mut first,
                    &request_mac,
                    17,
                    100,
                    30,
                    crate::TsigErrorCode::NoError,
                    vec![],
                    Some(length),
                )
                .unwrap();
            let first_wire = first.into_wire().unwrap();
            let split = split_tsig(&first_wire).unwrap();
            let input = standard_mac_input(Some(&request_mac), &split.unsigned_wire, &split.record);
            assert_eq!(prior, legacy(algorithm, &secret, &input)[..length]);
            let mut middle = request();
            middle.headers.qr = true;
            let middle_wire = middle.into_wire().unwrap();
            let mut last = middle.clone();
            let mut tsig = Tsig {
                algorithm: algorithm.name(),
                time_signed: 101,
                fudge: 30,
                mac: vec![],
                original_id: 17,
                error: TsigErrorCode::NoError,
                other_data: vec![],
            };
            let input = stream_mac_input(&prior, &middle_wire, &last.into_wire().unwrap(), &tsig);
            tsig.mac = legacy(algorithm, &secret, &input)[..length].to_vec();
            last.additionals.push(tsig_record(owner.clone(), tsig));
            let last_wire = last.into_wire().unwrap();
            let mut verifier = TsigStreamVerifier::new(key.clone(), request_mac.clone());
            verifier
                .verify_next(&first_wire, 100, false)
                .unwrap()
                .unwrap();
            assert!(
                verifier
                    .verify_next(&middle_wire, 100, false)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                verifier
                    .verify_next(&last_wire, 101, true)
                    .unwrap()
                    .unwrap()
                    .messages
                    .len(),
                2
            );
            // An otherwise well-formed unsigned frame is withheld and authenticated by the next tag.
            let mut bad_middle = middle_wire.clone();
            bad_middle[1] ^= 1;
            let mut verifier = TsigStreamVerifier::new(key.clone(), request_mac.clone());
            verifier.verify_next(&first_wire, 100, false).unwrap();
            verifier.verify_next(&bad_middle, 100, false).unwrap();
            assert!(matches!(
                verifier.verify_next(&last_wire, 101, true),
                Err(TsigAuthenticationError::BadSignature)
            ));
        }
    }
}

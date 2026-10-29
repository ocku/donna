use dns::Message;

/// Builds the minimal response before attaching a fresh TSIG or SIG(0).
/// RFC 6891 §7 requires OPT even with TC. Keep its response code and flags,
/// while dropping optional payloads that might themselves exceed the limit.
pub(super) fn truncated(query: &Message, response: &Message) -> Message {
    let additionals = response
        .edns()
        .ok()
        .flatten()
        .map(|mut edns| {
            edns.options.clear();
            edns.into_record()
        })
        .into_iter()
        .collect();
    let mut headers = response.headers.clone();
    headers.tc = true;
    Message {
        headers,
        questions: query.questions.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{Edns, EdnsOption, Headers, IntoWire, RCode, TsigAlgorithm, TsigKey};

    fn extended_error() -> Message {
        Message::builder()
            .headers(Headers {
                qr: true,
                rcode: RCode::Refused,
                ..Headers::default()
            })
            .additionals([Edns {
                extended_rcode: 1,
                dnssec_ok: true,
                options: vec![EdnsOption {
                    code: 65001,
                    data: vec![0; 1024],
                }],
                ..Edns::default()
            }
            .into_record()])
            .build()
            .unwrap()
    }

    #[test]
    fn minimal_signed_reply_keeps_extended_error_and_omits_optional_payload() {
        let query = Message::builder().build().unwrap();
        let response = Message::builder()
            .headers(Headers {
                qr: true,
                rcode: RCode::Refused,
                ..Headers::default()
            })
            .additionals([Edns {
                extended_rcode: 1,
                dnssec_ok: true,
                options: vec![EdnsOption {
                    code: 65001,
                    data: vec![0; 512],
                }],
                ..Edns::default()
            }
            .into_record()])
            .build()
            .unwrap();
        let reply = truncated(&query, &response);
        assert!(reply.headers.tc);
        assert_eq!(reply.headers.rcode, RCode::Refused);
        let edns = reply.edns().unwrap().unwrap();
        assert_eq!(edns.extended_rcode, 1);
        assert!(edns.dnssec_ok);
        assert!(edns.options.is_empty());
    }

    fn assert_extended_error(response: &Message, wire: &[u8]) {
        assert!(wire.len() <= 512);
        assert!(response.headers.tc);
        assert_eq!(response.extended_rcode(), 21);
        let edns = response.edns().unwrap().unwrap();
        assert!(edns.dnssec_ok);
        assert!(edns.options.is_empty());
    }

    #[test]
    fn tsig_truncation_signs_the_retained_extended_error() {
        let key = TsigKey::new(
            dns::DomainName::from_dotted("key.example.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![1; 32],
        )
        .unwrap();
        let now = super::super::tsig::unix_time_now();
        let mut query = Message::builder()
            .additionals([Edns::new(512).into_record()])
            .build()
            .unwrap();
        let mac = key.sign_request(&mut query, now, 300, None).unwrap();
        let mut response = extended_error();
        super::super::tsig::sign_response(
            &key,
            &mac,
            0,
            300,
            &mut response,
            &query,
            transport::TransportProtocol::Udp,
        )
        .unwrap();
        let wire = response.into_wire().unwrap();
        let verified = key.verify_response(&wire, &mac, now).unwrap();
        assert_extended_error(&verified.message, &wire);
    }

    #[test]
    fn sig0_truncation_signs_the_retained_extended_error() {
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let key = dns::Sig0SigningKey::from_ed25519_pkcs8(
            dns::DomainName::from_dotted("key.example.").unwrap(),
            0,
            3,
            pkcs8.as_ref(),
        )
        .unwrap();
        let now = super::super::sig0::unix_time_now();
        let mut query = Message::builder()
            .additionals([Edns::new(512).into_record()])
            .build()
            .unwrap();
        key.sign_request(&mut query, now as u32 - 60, now as u32 + 60)
            .unwrap();
        let request_wire = query.clone().into_wire().unwrap();
        let mut response = extended_error();
        super::super::sig0::sign_response(
            &key,
            &request_wire,
            &mut response,
            &query,
            transport::TransportProtocol::Udp,
        )
        .unwrap();
        let wire = response.into_wire().unwrap();
        let verified = key
            .verification_key()
            .verify_response(&wire, &request_wire, now)
            .unwrap();
        assert_extended_error(&verified.message, &wire);
    }
}

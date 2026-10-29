use super::*;

#[tokio::test]
async fn edns_context_preserves_error_precedence_and_do_for_both_handler_paths() {
    let server = server();
    for placement in ["valid", "duplicate", "misplaced"] {
        for bits in 0..64 {
            let unsupported = bits & 1 != 0;
            let malformed_option = bits & 2 != 0;
            let extended_rcode = bits & 4 != 0;
            let malformed_header = bits & 8 != 0;
            let dnssec_ok = bits & 16 != 0;
            let mut query = request(false);
            query.headers.aa = malformed_header;
            let opt = Edns {
                version: u8::from(unsupported),
                extended_rcode: u8::from(extended_rcode),
                dnssec_ok,
                z: if bits & 32 != 0 { 0x0123 } else { 0 },
                options: vec![dns::EdnsOption {
                    code: if malformed_option {
                        dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE
                    } else {
                        65000
                    },
                    data: if malformed_option {
                        vec![0]
                    } else {
                        vec![7; 64]
                    },
                }],
                ..Edns::new(1232)
            }
            .into_record();
            match placement {
                "duplicate" => query.additionals = vec![opt.clone(), opt],
                "misplaced" => query.answers.push(opt),
                _ => query.additionals.push(opt),
            }
            let expected_rcode = if placement != "valid" {
                1
            } else if unsupported && !malformed_option {
                16
            } else if malformed_option || extended_rcode || malformed_header {
                1
            } else {
                5
            };
            let ordinary = server.answer(&query).await;
            let immediate = server
                .try_handle(
                    &query,
                    &[],
                    (Ipv4Addr::LOCALHOST, 1234).into(),
                    transport::TransportProtocol::Udp,
                )
                .unwrap();
            assert_eq!(
                ordinary.extended_rcode(),
                expected_rcode,
                "{placement} flags={bits}"
            );
            let response_edns = ordinary.edns().unwrap().unwrap();
            assert_eq!(response_edns.dnssec_ok, placement == "valid" && dnssec_ok);
            assert_eq!(response_edns.version, 0);
            assert_eq!(response_edns.z, 0);
            let udp = server
                .try_handle_udp(&query, &[], (Ipv4Addr::LOCALHOST, 1234).into(), 1232)
                .unwrap();
            let udp = match udp {
                transport::ImmediateUdpResponse::Message(message) => message,
                transport::ImmediateUdpResponse::Encoded(message) => {
                    message.into_message().unwrap()
                }
            };
            assert_eq!(ordinary.into_wire().unwrap(), udp.into_wire().unwrap());
            assert_eq!(
                ordinary.into_wire().unwrap(),
                immediate.into_wire().unwrap()
            );
        }
    }
}

#[tokio::test]
async fn immediate_cached_answers_keep_client_flags_questions_and_edns_policy() {
    let server = server();
    let peer = (Ipv4Addr::LOCALHOST, 1234).into();
    let protocol = transport::TransportProtocol::Udp;
    let cold = request(true);
    assert!(server.try_handle(&cold, &[], peer, protocol).is_none());
    server.answer(&cold).await;
    for bits in 0..16 {
        let mut request = request(bits & 1 != 0);
        request.headers.cd = bits & 2 != 0;
        request.headers.ad = bits & 4 != 0;
        request.questions[0].qname = DomainName::from_dotted("EXAMPLE.com.").unwrap();
        request.additionals.push(
            Edns {
                dnssec_ok: bits & 8 != 0,
                ..Edns::default()
            }
            .into_record(),
        );
        let mut immediate = server.try_handle(&request, &[], peer, protocol).unwrap();
        let mut ordinary = server.answer(&request).await;
        assert_eq!(
            immediate.questions[0].qname.as_ref(),
            request.questions[0].qname.as_ref()
        );
        assert_eq!(immediate.answers.len(), ordinary.answers.len());
        for (actual, expected) in immediate.answers.iter().zip(&ordinary.answers) {
            assert_eq!(actual.rdata, expected.rdata);
            assert!(actual.ttl >= expected.ttl);
            assert!(actual.ttl <= 60);
        }
        for response in [&mut immediate, &mut ordinary] {
            for record in response.answers.iter_mut().chain(&mut response.authorities) {
                record.ttl = 0;
            }
        }
        assert_eq!(
            immediate.into_wire().unwrap(),
            ordinary.into_wire().unwrap()
        );
    }
    let mut invalid = request(true);
    invalid.headers.aa = true;
    assert_eq!(
        server
            .try_handle(&invalid, &[], peer, protocol)
            .unwrap()
            .headers
            .rcode,
        RCode::FormatError
    );
}

use super::*;
use transport::{DnsRequestHandler, ImmediateUdpResponse};

#[tokio::test]
async fn borrowed_positives_match_structured_flags_types_case_options_and_fallbacks() {
    for source in [
        include_str!("../../zone/tests/fixtures/bind-nsec.zone"),
        include_str!("../../zone/tests/fixtures/bind-nsec3.zone"),
    ] {
        let server = NameServer::new();
        let apex = DomainName::from_dotted("example.test.").unwrap();
        server
            .install(
                Zone::from_master(apex.clone(), MasterFile::parse(source, Some(apex)).unwrap())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut encoded_count = 0;
        for text in [
            "www.example.test.",
            "WWW.EXAMPLE.TEST.",
            "m.wild.example.test.",
            "p.q.WILD.EXAMPLE.TEST.",
            "alias.example.test.",
            "example.test.",
            "child.example.test.",
        ] {
            for qtype in [
                QueryType::A,
                QueryType::AAAA,
                QueryType::TXT,
                QueryType::CNAME,
                QueryType::NS,
                QueryType::MX,
                QueryType::DNSKEY,
                QueryType::RRSIG,
                QueryType::NSEC,
                QueryType::ANY,
            ] {
                for mode in 0..4 {
                    for flags in 0..8 {
                        let mut query = Message::builder()
                            .questions([Question {
                                qname: DomainName::from_dotted(text).unwrap(),
                                qtype,
                                qclass: QClassType::Class(ClassType::IN),
                            }])
                            .build()
                            .unwrap();
                        query.headers.rd = flags & 1 != 0;
                        query.headers.ad = flags & 2 != 0;
                        query.headers.cd = flags & 4 != 0;
                        if mode > 0 {
                            let mut edns = dns::Edns {
                                dnssec_ok: mode > 1,
                                ..dns::Edns::new(1232)
                            };
                            if mode == 3 {
                                edns.options.push(dns::EdnsOption {
                                    code: 65000,
                                    data: vec![1],
                                });
                            }
                            query.additionals.push(edns.into_record());
                        }
                        let packet = query.into_wire().unwrap();
                        let peer = (Ipv4Addr::LOCALHOST, 1234).into();
                        let expected = server
                            .try_handle(&query, &packet, peer, TransportProtocol::Udp)
                            .unwrap()
                            .into_wire()
                            .unwrap();
                        let actual =
                            match server.try_handle_udp(&query, &packet, peer, 1232).unwrap() {
                                ImmediateUdpResponse::Encoded(reply) => {
                                    assert!(reply.matches_request(&query));
                                    encoded_count += 1;
                                    reply.into_bytes()
                                }
                                ImmediateUdpResponse::Message(reply) => reply.into_wire().unwrap(),
                            };
                        assert_eq!(
                            actual, expected,
                            "name={text} type={qtype:?} mode={mode} flags={flags}"
                        );
                    }
                }
            }
        }
        assert!(
            encoded_count > 100,
            "ordinary positives must exercise borrowed encoding"
        );
    }
}

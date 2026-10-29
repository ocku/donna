use super::*;
use transport::{DnsRequestHandler, ImmediateUdpResponse};

// RFC 4592 section 3.3.3 makes a wildcard type miss NODATA. RFC 5155
// section 7.2.5 additionally requires the expansion's closest-encloser proof;
// a prepared denial for the literal wildcard must not replace that selection.
#[tokio::test]
async fn literal_wildcard_nodata_preparation_cannot_supply_expanded_denials() {
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
        for dnssec_ok in [false, true] {
            let literal = query_with_do(
                DomainName::from_dotted("*.wild.example.test.").unwrap(),
                QueryType::A,
                dnssec_ok,
            );
            for _ in 0..40 {
                assert!(server.try_handle_udp(&literal, &[], peer(), 1232).is_some());
            }
            {
                let zones = server.zones.read().await.unwrap();
                let zone =
                    crate::server::zone_index::authoritative_zone(&zones, &literal.questions[0])
                        .unwrap();
                assert!(
                    zone.nodata_cache(&literal.questions[0].qname)
                        .unwrap()
                        .render(&literal, dnssec_ok, 1232)
                        .is_some()
                );
            }
            for owner in ["m.wild.example.test.", "other.wild.example.test."] {
                let query = query_with_do(
                    DomainName::from_dotted(owner).unwrap(),
                    QueryType::A,
                    dnssec_ok,
                );
                let expected = server.handle(query.clone()).await;
                assert_eq!(expected.headers.rcode, RCode::Ok);
                assert!(expected.headers.aa);
                assert!(expected.answers.is_empty());
                assert!(
                    expected
                        .authorities
                        .iter()
                        .any(|rr| rr.rtype == RecordType::SOA)
                );
                for _ in 0..40 {
                    let actual = match server.try_handle_udp(&query, &[], peer(), 1232).unwrap() {
                        ImmediateUdpResponse::Message(reply) => reply,
                        ImmediateUdpResponse::Encoded(reply) => {
                            assert!(reply.matches_request(&query));
                            reply.into_message().unwrap()
                        }
                    };
                    assert_eq!(actual.into_wire().unwrap(), expected.into_wire().unwrap());
                }
            }
        }
    }
}

fn peer() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 1234).into()
}

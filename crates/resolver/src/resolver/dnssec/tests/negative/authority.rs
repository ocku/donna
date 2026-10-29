//! Authority metadata cannot inherit the authentication of a cached denial.
use super::super::{fixtures::resolver, negative::negative_fixture, support::name};
use dns::{ClassType, Message, Question, RData, RecordType, ResourceRecord};
use std::{net::Ipv4Addr, time::Duration};

#[tokio::test]
async fn aggressive_negative_ad_never_promotes_an_implicit_unsigned_authority_ns() {
    use dns::FromWire;
    let (transport, anchor, source) = negative_fixture();
    let resolver = resolver(transport, anchor);
    resolver.resolve(source.clone()).await.unwrap();
    let address = (Ipv4Addr::LOCALHOST, 53).into();
    resolver.delegation_cache.insert(
        &crate::protocol::Referral {
            zone: name(&["example"]),
            class: ClassType::IN,
            candidates: vec![address],
            candidate_ttls: vec![(address, Duration::from_secs(60))],
            trusted_glue: vec![],
            name_servers: vec![name(&["ns", "example"])],
            ttl: Duration::from_secs(60),
        },
        Duration::from_secs(60),
    );
    for question in [
        source.clone(),
        Question {
            qname: name(&["child", "missing", "example"]),
            ..source
        },
    ] {
        let response = resolver
            .cached_client_response(&question)
            .unwrap()
            .unwrap()
            .response;
        assert!(response.headers.ad);
        assert!(
            !response
                .authorities
                .iter()
                .any(|rr| rr.rtype == RecordType::NS),
            "delegation-cache NS has no authenticated authority provenance"
        );
        let request = Message {
            headers: dns::Headers {
                rd: true,
                ..dns::Headers::default()
            },
            questions: vec![question],
            answers: vec![],
            authorities: vec![],
            additionals: vec![
                dns::Edns {
                    dnssec_ok: true,
                    ..dns::Edns::default()
                }
                .into_record(),
            ],
        };
        let response = match resolver
            .cached_client_response_udp(&request, 1232)
            .unwrap()
            .unwrap()
        {
            transport::ImmediateUdpResponse::Message(reply) => reply,
            transport::ImmediateUdpResponse::Encoded(reply) => {
                Message::from_wire(reply.as_bytes()).unwrap()
            }
        };
        assert!(response.headers.ad);
        assert!(
            !response
                .authorities
                .iter()
                .any(|rr| rr.rtype == RecordType::NS),
            "encoded cache path must preserve the same authenticated authority contract"
        );
    }
}

#[tokio::test]
async fn aggressive_negative_source_ns_never_inherits_authenticated_denial_status() {
    let (mut transport, anchor, question) = negative_fixture();
    let authenticated = transport.answer.authorities.clone();
    // A Type1 source packet supplies optional NS metadata with no signature.
    // Authentication of the independently signed SOA/NSEC cannot authenticate it.
    transport.answer.authorities.push(ResourceRecord {
        name: name(&["example"]),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 300,
        rdata: RData::NS(name(&["unproven", "example"])),
    });
    for (rtype, rdata) in [
        (RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 99))),
        (RecordType::TXT, RData::TXT(vec![b"unproven".to_vec()])),
        (
            RecordType::NSEC,
            RData::NSEC(dns::Nsec {
                next_domain_name: name(&["example"]),
                type_bitmap: dns::TypeBitmap::new(vec![u16::from(RecordType::A)]).unwrap(),
            }),
        ),
    ] {
        transport.answer.authorities.push(ResourceRecord {
            name: name(&["unused", "example"]),
            rtype,
            class: ClassType::IN,
            ttl: 300,
            rdata,
        });
    }
    let resolver = resolver(transport, anchor);
    let address = (Ipv4Addr::LOCALHOST, 53).into();
    resolver.delegation_cache.insert(
        &crate::protocol::Referral {
            zone: name(&["example"]),
            class: ClassType::IN,
            candidates: vec![address],
            candidate_ttls: vec![(address, Duration::from_secs(60))],
            trusted_glue: vec![],
            name_servers: vec![name(&["ns", "example"])],
            ttl: Duration::from_secs(60),
        },
        Duration::from_secs(60),
    );
    let fresh = resolver.resolve(question.clone()).await.unwrap();
    let cached = resolver
        .cached_client_response(&question)
        .unwrap()
        .unwrap()
        .response;
    for response in [fresh, cached] {
        assert!(
            response.headers.ad,
            "unproven optional metadata need not downgrade a genuine denial"
        );
        assert_eq!(response.authorities.len(), authenticated.len());
        assert!(
            response
                .authorities
                .iter()
                .all(|rr| authenticated.iter().any(|source| source.eq_dns(rr))),
            "unsigned source NS/A/TXT and unused NSEC cannot inherit the denial's authenticated status"
        );
    }
}

#[test]
fn aggressive_negative_authority_projection_preserves_individual_ttl_indices() {
    let question = Question {
        qname: name(&["query", "example"]),
        qtype: dns::QueryType::TXT,
        qclass: dns::QClassType::Class(ClassType::IN),
    };
    let record = |label, ttl| ResourceRecord {
        name: name(&[label, "example"]),
        rtype: RecordType::TXT,
        class: ClassType::IN,
        ttl,
        rdata: RData::TXT(vec![b"value".to_vec()]),
    };
    let mut response = Message {
        headers: dns::Headers::default(),
        questions: vec![question],
        answers: vec![],
        authorities: vec![
            record("drop", 1),
            record("keep", 40),
            record("drop", 2),
            record("keep", 80),
            record("drop", 3),
            record("keep", 60),
        ],
        additionals: vec![],
    };
    let at = std::time::Instant::now();
    let mut ttls = super::super::super::response_ttls::ResponseTtls::capture(&response, at);
    ttls.retain_authorities(&mut response, |rr| {
        rr.name.eq_dns(&name(&["keep", "example"]))
    });
    ttls.clamp(&mut response, at + Duration::from_secs(3))
        .unwrap();
    assert_eq!(
        response
            .authorities
            .iter()
            .map(|rr| rr.ttl)
            .collect::<Vec<_>>(),
        vec![37, 77, 57]
    );
}

use super::*;
use transport::{DnsRequestHandler, ImmediateUdpResponse};

const SIGNED_ZONES: [&str; 2] = [
    include_str!("../../zone/tests/fixtures/bind-nsec.zone"),
    include_str!("../../zone/tests/fixtures/bind-nsec3.zone"),
];

fn unprepared_server() -> NameServer {
    NameServer::new()
}

fn packet(server: &NameServer, request: &Message, maximum: usize) -> Vec<u8> {
    optional_packet(server, request, maximum).unwrap()
}

fn optional_packet(server: &NameServer, request: &Message, maximum: usize) -> Option<Vec<u8>> {
    Some(
        match server.try_handle_udp(request, &[], (Ipv4Addr::LOCALHOST, 1234).into(), maximum)? {
            ImmediateUdpResponse::Encoded(reply) => {
                assert!(reply.matches_request(request));
                reply.as_bytes().to_vec()
            }
            ImmediateUdpResponse::Message(reply) => reply.into_wire().unwrap(),
        },
    )
}

async fn install_signed(server: &NameServer, source: &str) {
    let apex = DomainName::from_dotted("example.test.").unwrap();
    server
        .install(
            Zone::from_master(apex.clone(), MasterFile::parse(source, Some(apex)).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();
}

fn question(owner: &str, dnssec_ok: bool) -> Message {
    let mut request = query_with_do(
        DomainName::from_dotted(owner).unwrap(),
        QueryType::A,
        dnssec_ok,
    );
    request.additionals = vec![
        dns::Edns {
            dnssec_ok,
            ..dns::Edns::new(1232)
        }
        .into_record(),
    ];
    request
}

// The first packet uses the ordinary checked writer. Exact bytes after warmup
// catch stale compression targets, authority ordering, flags, TTLs and proofs.
#[tokio::test]
async fn prepared_negative_warm_packets_keep_current_wire_and_request_policy() {
    for source in SIGNED_ZONES {
        for owner in [
            "absent.example.test.",
            "m.wild.example.test.",
            "empty.example.test.",
        ] {
            for dnssec_ok in [false, true] {
                let server = NameServer::new();
                install_signed(&server, source).await;
                let original = question(owner, dnssec_ok);
                let cold = packet(&server, &original, 1232);
                for _ in 0..40 {
                    assert_eq!(packet(&server, &original, 1232), cold);
                }
                // A fresh immutable zone has not admitted any exact NODATA
                // packet, so every oracle query uses the ordinary writer.
                for bits in 0..16 {
                    for maximum in [12, 64, 512, 1232, 4096] {
                        let fresh = unprepared_server();
                        install_signed(&fresh, source).await;
                        let mut request = original.clone();
                        request.headers.id = 1700 + bits;
                        request.headers.rd = bits & 1 != 0;
                        request.headers.cd = bits & 2 != 0;
                        request.headers.ad = bits & 4 != 0;
                        request.additionals[0].class = ClassType::Unknown(4096);
                        if bits & 8 != 0 && !dnssec_ok {
                            request.additionals.clear();
                        }
                        assert_eq!(
                            packet(&server, &request, maximum),
                            packet(&fresh, &request, maximum),
                            "{owner}, DO={dnssec_ok}, flags={bits}, maximum={maximum}"
                        );
                    }
                }
                for mutation in 0..8 {
                    let fresh = unprepared_server();
                    install_signed(&fresh, source).await;
                    let mut request = original.clone();
                    match mutation {
                        0 => {
                            request.questions[0].qname =
                                DomainName::from_dotted(&owner.to_ascii_uppercase()).unwrap()
                        }
                        1 => request.questions[0].qtype = QueryType::AAAA,
                        2 => request.questions[0].qtype = QueryType::DS,
                        3 => request.questions[0].qtype = QueryType::ANY,
                        4 => request.questions[0].qtype = QueryType::Unknown(65000),
                        5 => request.questions[0].qclass = QClassType::Class(ClassType::CH),
                        6 => {
                            if let RData::OPT(options) = &mut request.additionals[0].rdata {
                                options.push(dns::EdnsOption {
                                    code: 65000,
                                    data: vec![1],
                                });
                            }
                        }
                        _ => request.additionals[0].ttl |= 1 << 16,
                    }
                    assert_eq!(
                        optional_packet(&server, &request, 1232),
                        optional_packet(&fresh, &request, 1232)
                    );
                }
                for mutation in 0..5 {
                    let mut request = original.clone();
                    match mutation {
                        0 => request.headers.aa = true,
                        1 => request.headers.ra = true,
                        2 => request.headers.tc = true,
                        3 => request.headers.qr = true,
                        _ => request.additionals.push(request.additionals[0].clone()),
                    }
                    assert!(server.try_handle_udp(
                        &request, &[], (Ipv4Addr::LOCALHOST, 1234).into(), 1232,
                    ).is_none());
                }
            }
        }
    }
}

// RFC 4035 3.1.3.2/.4 and RFC 5155 7.2.2/.5 require proofs for the actual
// expanded QNAME. A warmed exact packet must never cover another expansion,
// empty nonterminal, literal wildcard, closer encloser or delegation.
#[tokio::test]
async fn prepared_negative_does_not_cross_question_or_proof_provenance() {
    for source in SIGNED_ZONES {
        let server = NameServer::new();
        install_signed(&server, source).await;
        for dnssec_ok in [false, true] {
            for owner in ["absent.example.test.", "m.wild.example.test."] {
                let hot = question(owner, dnssec_ok);
                for _ in 0..40 {
                    packet(&server, &hot, 1232);
                }
            }
            for owner in [
                "other.example.test.",
                "a.absent.example.test.",
                "other.wild.example.test.",
                "0.wild.example.test.",
                "zz.wild.example.test.",
                "a.wild.example.test.",
                "deep.m.wild.example.test.",
                "*.wild.example.test.",
                "wild.example.test.",
                "empty.example.test.",
                "child.example.test.",
                "below.child.example.test.",
                "example.test.",
            ] {
                for qtype in [QueryType::A, QueryType::TXT, QueryType::DS] {
                    let fresh = unprepared_server();
                    install_signed(&fresh, source).await;
                    let mut request = question(owner, dnssec_ok);
                    request.questions[0].qtype = qtype;
                    assert_eq!(
                        packet(&server, &request, 1232),
                        packet(&fresh, &request, 1232)
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn prepared_negative_publication_rechecks_answer_nodata_and_referral() {
    let apex = name(&["example"]);
    let owner = name(&["missing", "example"]);
    for replacement in 0..4 {
        let server = NameServer::new();
        server
            .install(make_zone(apex.clone(), ClassType::IN, 60, vec![]))
            .await
            .unwrap();
        let request = query_with_do(owner.clone(), QueryType::A, false);
        for _ in 0..40 {
            assert_eq!(
                Message::from_wire(&packet(&server, &request, 1232))
                    .unwrap()
                    .headers
                    .rcode,
                RCode::NameError
            );
        }
        let rr = match replacement {
            0 => record(
                owner.clone(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 99)),
            ),
            1 => record(
                owner.clone(),
                RecordType::TXT,
                RData::TXT(vec![b"exists".to_vec()]),
            ),
            2 => record(
                owner.clone(),
                RecordType::NS,
                RData::NS(name(&["ns", "invalid"])),
            ),
            _ => record(
                name(&["*", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 100)),
            ),
        };
        let mut records = make_zone(apex.clone(), ClassType::IN, 7, vec![rr])
            .records()
            .to_vec();
        for rr in &mut records {
            if let RData::SOA { serial, .. } = &mut rr.rdata {
                *serial = 2;
            }
        }
        assert!(matches!(
            server
                .install(Zone::from_master(apex.clone(), MasterFile { records }).unwrap())
                .await
                .unwrap(),
            InstallOutcome::Replaced
        ));
        let response = Message::from_wire(&packet(&server, &request, 1232)).unwrap();
        assert_eq!(response.headers.rcode, RCode::Ok);
        match replacement {
            0 | 3 => assert_eq!(response.answers.len(), 1),
            1 => {
                assert!(response.answers.is_empty());
                assert!(response.headers.aa);
                assert!(response.authorities.iter().all(|rr| rr.ttl <= 7));
            }
            _ => {
                assert!(!response.headers.aa);
                assert!(
                    response
                        .authorities
                        .iter()
                        .any(|rr| rr.rtype == RecordType::NS)
                );
                assert!(
                    !response
                        .authorities
                        .iter()
                        .any(|rr| rr.rtype == RecordType::SOA)
                );
            }
        }
    }
}

#[tokio::test]
async fn prepared_negative_respects_publication_lock_and_new_closer_zone() {
    let server = NameServer::new();
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    server
        .install(make_zone(apex, ClassType::IN, 30, vec![]))
        .await
        .unwrap();
    let request = query_with_do(child.clone(), QueryType::A, false);
    for _ in 0..40 {
        packet(&server, &request, 1232);
    }
    let guard = server.zones.write().await;
    assert!(optional_packet(&server, &request, 1232).is_none());
    drop(guard);
    server
        .install(make_zone(
            child.clone(),
            ClassType::IN,
            11,
            vec![record(
                child.clone(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 88)),
            )],
        ))
        .await
        .unwrap();
    let response = Message::from_wire(&packet(&server, &request, 1232)).unwrap();
    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].name, child);
}

#[tokio::test]
async fn prepared_negative_udp_truncation_matches_cold_complete_rrset_handling() {
    let mut truncated = 0;
    for source in SIGNED_ZONES {
        for owner in ["absent.example.test.", "m.wild.example.test."] {
            let hot = NameServer::new();
            let cold = unprepared_server();
            install_signed(&hot, source).await;
            install_signed(&cold, source).await;
            let mut request = question(owner, true);
            let full_length = packet(&hot, &request, 1232).len();
            for _ in 0..40 {
                packet(&hot, &request, 1232);
            }
            request.additionals[0].class = ClassType::Unknown(512);
            let wire = request.into_wire().unwrap();
            let mut replies = vec![];
            for server in [hot, cold] {
                let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                let address = reservation.local_addr().unwrap();
                drop(reservation);
                let listener = tokio::spawn(UdpTransport.serve(address, server));
                replies.push(raw_udp_exchange(address, &wire).await);
                listener.abort();
                assert!(listener.await.unwrap_err().is_cancelled());
            }
            assert_eq!(replies[0], replies[1]);
            assert!(replies[0].len() <= 512);
            let reply = Message::from_wire(&replies[0]).unwrap();
            assert_eq!(reply.headers.tc, full_length > 512);
            truncated += usize::from(reply.headers.tc);
        }
    }
    assert!(
        truncated > 0,
        "fixtures must exercise whole-RRset truncation"
    );
}

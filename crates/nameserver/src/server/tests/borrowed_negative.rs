use super::*;
use transport::{DnsRequestHandler, ImmediateUdpResponse};

fn ready(server: &NameServer, query: &Message, maximum: usize) -> Option<ImmediateUdpResponse> {
    server.try_handle_udp(query, &[], (Ipv4Addr::LOCALHOST, 1234).into(), maximum)
}

fn into_message(reply: ImmediateUdpResponse, request: &Message) -> (Message, bool) {
    match reply {
        ImmediateUdpResponse::Message(reply) => (reply, false),
        ImmediateUdpResponse::Encoded(reply) => {
            assert!(reply.matches_request(request));
            (reply.into_message().unwrap(), true)
        }
    }
}

async fn has_prepared_nodata(server: &NameServer, query: &Message) -> bool {
    let zones = server.zones.read().await.unwrap();
    let zone = crate::server::zone_index::authoritative_zone(&zones, &query.questions[0]).unwrap();
    zone.nodata_cache(&query.questions[0].qname)
        .is_some_and(|cache| {
            cache
                .render(
                    query,
                    query.edns().unwrap().is_some_and(|edns| edns.dnssec_ok),
                    1232,
                )
                .is_some()
        })
}

#[tokio::test]
async fn prepared_nodata_matches_current_flags_payloads_and_structured_records() {
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
            let mut initial = query_with_do(
                DomainName::from_dotted("empty.example.test.").unwrap(),
                QueryType::A,
                dnssec_ok,
            );
            initial.additionals = vec![
                dns::Edns {
                    dnssec_ok,
                    ..dns::Edns::new(1232)
                }
                .into_record(),
            ];
            initial.headers.cd = true;
            initial.headers.ad = true;
            // Invalid response-only query flags must be rejected before any
            // prepared-variant admission, even when repeated past warmup.
            for mutation in 0..4 {
                let mut invalid = initial.clone();
                match mutation {
                    0 => invalid.headers.aa = true,
                    1 => invalid.headers.ra = true,
                    2 => invalid.headers.tc = true,
                    _ => invalid.headers.rcode = RCode::Refused,
                }
                for _ in 0..40 {
                    assert!(ready(&server, &invalid, 1232).is_none());
                }
                assert_eq!(
                    server.handle(invalid).await.headers.rcode,
                    RCode::FormatError
                );
            }
            assert!(!has_prepared_nodata(&server, &initial).await);
            for _ in 0..40 {
                ready(&server, &initial, 1232).unwrap();
            }
            assert!(has_prepared_nodata(&server, &initial).await);
            for bits in 0..16 {
                for payload in [0, 128, 512, 1232, 4096, 65535] {
                    let mut query = initial.clone();
                    query.headers.id = 600 + bits;
                    query.headers.rd = bits & 1 != 0;
                    query.headers.cd = bits & 2 != 0;
                    query.headers.ad = bits & 4 != 0;
                    query.additionals[0].class = ClassType::Unknown(payload);
                    if bits & 8 != 0 && !dnssec_ok {
                        query.additionals.clear();
                    }
                    let (actual, _) = into_message(ready(&server, &query, 1232).unwrap(), &query);
                    assert_eq!(
                        actual.into_wire().unwrap(),
                        server.handle(query).await.into_wire().unwrap()
                    );
                }
            }
            let mut changed = initial.clone();
            changed.questions[0].qtype = QueryType::AAAA;
            assert!(!has_prepared_nodata(&server, &changed).await);
            let (actual, _) = into_message(ready(&server, &changed, 1232).unwrap(), &changed);
            assert_eq!(
                actual.into_wire().unwrap(),
                server.handle(changed).await.into_wire().unwrap()
            );
            let mut changed_case = initial.clone();
            changed_case.questions[0].qname =
                DomainName::from_dotted("Empty.Example.TEST.").unwrap();
            assert!(!has_prepared_nodata(&server, &changed_case).await);
            let (actual, _) =
                into_message(ready(&server, &changed_case, 1232).unwrap(), &changed_case);
            assert_eq!(
                actual.into_wire().unwrap(),
                server.handle(changed_case).await.into_wire().unwrap()
            );
            let mut options = initial.clone();
            if let RData::OPT(options) = &mut options.additionals[0].rdata {
                options.push(dns::EdnsOption {
                    code: 65001,
                    data: vec![1],
                });
            }
            assert!(!has_prepared_nodata(&server, &options).await);
            let (actual, _) = into_message(ready(&server, &options, 1232).unwrap(), &options);
            assert_eq!(
                actual.into_wire().unwrap(),
                server.handle(options).await.into_wire().unwrap()
            );
        }
    }
}

#[tokio::test]
async fn prepared_nodata_keeps_wildcard_and_nonexistent_owners_out_of_the_cache() {
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
            // Warming the literal wildcard node must not let expanded names
            // reuse its denial: their next-closer proofs depend on QNAME.
            for owner in [
                "*.wild.example.test.",
                "m.wild.example.test.",
                "other.wild.example.test.",
                "missing.example.test.",
            ] {
                let query = query_with_do(
                    DomainName::from_dotted(owner).unwrap(),
                    QueryType::TXT,
                    dnssec_ok,
                );
                for _ in 0..40 {
                    let (actual, _) = into_message(ready(&server, &query, 1232).unwrap(), &query);
                    assert_eq!(
                        actual.into_wire().unwrap(),
                        server.handle(query.clone()).await.into_wire().unwrap(),
                        "{owner}, DO={dnssec_ok}"
                    );
                }
                if owner != "*.wild.example.test." {
                    assert!(!has_prepared_nodata(&server, &query).await);
                }
            }
        }
    }
}

#[tokio::test]
async fn prepared_nodata_node_budget_is_bounded_and_publication_discards_old_state() {
    let server = NameServer::new();
    let apex = name(&["example"]);
    let owners: Vec<_> = (0..65)
        .map(|i| DomainName::from_dotted(&format!("owner{i}.example.")).unwrap())
        .collect();
    let records: Vec<_> = owners
        .iter()
        .map(|owner| ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::TXT(vec![b"exists".to_vec()]),
        })
        .collect();
    server
        .install(make_zone(apex.clone(), ClassType::IN, 60, records.clone()))
        .await
        .unwrap();
    let mut prepared = 0;
    for owner in &owners {
        let query = query_with_do(owner.clone(), QueryType::A, false);
        for _ in 0..40 {
            ready(&server, &query, 1232).unwrap();
        }
        prepared += usize::from(has_prepared_nodata(&server, &query).await);
        let (actual, _) = into_message(ready(&server, &query, 1232).unwrap(), &query);
        assert_eq!(
            actual.into_wire().unwrap(),
            server.handle(query).await.into_wire().unwrap()
        );
    }
    assert_eq!(prepared, 64);
    let mut replacement = records;
    replacement.push(ResourceRecord {
        name: owners[0].clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 20,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 99)),
    });
    let mut replacement = make_zone(apex.clone(), ClassType::IN, 20, replacement)
        .records()
        .to_vec();
    for record in &mut replacement {
        if let RData::SOA { serial, .. } = &mut record.rdata {
            *serial += 1;
        }
    }
    assert!(matches!(
        server
            .install(
                Zone::from_master(
                    apex,
                    MasterFile {
                        records: replacement
                    }
                )
                .unwrap()
            )
            .await
            .unwrap(),
        InstallOutcome::Replaced
    ));
    let query = query_with_do(owners[0].clone(), QueryType::A, false);
    assert!(!has_prepared_nodata(&server, &query).await);
    let (actual, _) = into_message(ready(&server, &query, 1232).unwrap(), &query);
    assert_eq!(actual.answers.len(), 1);
    assert_eq!(
        actual.into_wire().unwrap(),
        server.handle(query).await.into_wire().unwrap()
    );
}

#[tokio::test]
async fn borrowed_negatives_match_the_structured_path_on_real_bind_snapshots() {
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
        for owner in [
            "empty.example.test.",
            "missing.example.test.",
            "www.example.test.",
            "alias.example.test.",
            "m.wild.example.test.",
            "child.example.test.",
            "Missing.Example.TEST.",
        ] {
            for qtype in [
                QueryType::A,
                QueryType::DS,
                QueryType::TXT,
                QueryType::Unknown(65000),
            ] {
                for bits in 0..32 {
                    let mut query = query_with_do(
                        DomainName::from_dotted(owner).unwrap(),
                        qtype,
                        bits & 1 != 0,
                    );
                    query.headers.rd = bits & 2 != 0;
                    query.headers.cd = bits & 4 != 0;
                    query.headers.ad = bits & 8 != 0;
                    if bits & 16 != 0 {
                        query.additionals.clear();
                    }
                    let (actual, encoded) =
                        into_message(ready(&server, &query, 1232).unwrap(), &query);
                    let expected = server.handle(query.clone()).await;
                    assert_eq!(
                        actual.into_wire().unwrap(),
                        expected.into_wire().unwrap(),
                        "{owner} {qtype:?} {bits}"
                    );
                    if owner == "empty.example.test." && qtype == QueryType::A {
                        assert!(encoded, "common NODATA must use borrowed records");
                    }
                }
            }
        }
        // Each owner is new; there is no warmup, per-name cache or template.
        for i in 0..100 {
            let labels = vec![vec![0, 255, i, b'A'], b"example".to_vec(), b"test".to_vec()];
            let query = query_with_do(DomainName::from_labels(labels).unwrap(), QueryType::A, true);
            let (actual, encoded) = into_message(ready(&server, &query, 1232).unwrap(), &query);
            assert!(encoded);
            assert_eq!(
                actual.into_wire().unwrap(),
                server.handle(query).await.into_wire().unwrap()
            );
        }
    }
}

#[tokio::test]
async fn borrowed_negative_replacement_and_unsupported_edns_preserve_normal_handling() {
    let server = NameServer::new();
    let owner = name(&["missing", "example"]);
    for ttl in [80, 20] {
        let apex = name(&["example"]);
        let snapshot = make_zone(apex.clone(), ClassType::IN, ttl, Vec::new());
        let mut records = snapshot.records().to_vec();
        for record in &mut records {
            if let RData::SOA { serial, .. } = &mut record.rdata {
                *serial = 100 - ttl;
            }
        }
        assert!(matches!(
            server
                .install(Zone::from_master(apex, MasterFile { records }).unwrap())
                .await
                .unwrap(),
            InstallOutcome::Installed | InstallOutcome::Replaced
        ));
        let query = query_with_do(owner.clone(), QueryType::A, true);
        let (actual, encoded) = into_message(ready(&server, &query, 64).unwrap(), &query);
        assert!(encoded); // Transport truncates this same selected packet.
        assert_eq!(
            actual.into_wire().unwrap(),
            server.handle(query.clone()).await.into_wire().unwrap()
        );
        assert!(actual.authorities.iter().all(|rr| rr.ttl <= ttl));
        let mut options = query;
        if let RData::OPT(options) = &mut options.additionals[0].rdata {
            options.push(dns::EdnsOption {
                code: 65001,
                data: vec![1, 2],
            });
        }
        let (actual, encoded) = into_message(ready(&server, &options, 1232).unwrap(), &options);
        assert!(!encoded);
        assert_eq!(
            actual.into_wire().unwrap(),
            server.handle(options).await.into_wire().unwrap()
        );
    }
    let guard = server.zones.write().await;
    let query = query_with_do(owner, QueryType::A, true);
    assert!(ready(&server, &query, 1232).is_none());
    drop(guard);
    assert!(ready(&server, &query, 1232).is_some());
}

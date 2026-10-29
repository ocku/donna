use super::*;

#[tokio::test]
async fn normal_ns_and_mx_answers_exclude_data_hidden_below_a_delegation() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);

    for (qtype, reference, target) in [
        (
            QueryType::NS,
            record(
                apex.clone(),
                RecordType::NS,
                RData::NS(name(&["ns", "child", "example"])),
            ),
            name(&["ns", "child", "example"]),
        ),
        (
            QueryType::MX,
            record(
                apex.clone(),
                RecordType::MX,
                RData::MX {
                    preference: 10,
                    exchange: name(&["mail", "child", "example"]),
                },
            ),
            name(&["mail", "child", "example"]),
        ),
    ] {
        let server = NameServer::new();
        server
            .install(make_zone(
                apex.clone(),
                ClassType::IN,
                300,
                vec![
                    reference,
                    record(
                        child.clone(),
                        RecordType::NS,
                        RData::NS(name(&["ns", "elsewhere"])),
                    ),
                    record(
                        target.clone(),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                    ),
                ],
            ))
            .await
            .unwrap();
        let query = Message::builder()
            .questions([Question {
                qname: apex.clone(),
                qtype,
                qclass: QClassType::Class(ClassType::IN),
            }])
            .build()
            .unwrap();

        let response = server.handle(query).await;

        assert_eq!(response.headers.rcode, RCode::Ok);
        assert!(response.headers.aa);
        assert!(response.additionals.is_empty());
    }
}

#[tokio::test]
async fn dynamic_update_is_disabled_without_durable_storage() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let request = update_request(
        [],
        [record(
            name(&["new", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 9)),
        )],
    );

    let response = server.handle(request).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(response.questions.is_empty());
}

#[tokio::test]
async fn dynamic_update_commits_a_complete_persisted_snapshot_and_advances_soa() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let server = update_server(Arc::clone(&persistence));
    server.install(test_zone()).await.unwrap();
    let added_name = name(&["added", "example"]);
    let request = update_request(
        [update_meta(
            added_name.clone(),
            RecordType::Unknown(255),
            254,
        )],
        [
            record(
                added_name.clone(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 9)),
            ),
            update_meta(name(&["www", "example"]), RecordType::A, 255),
        ],
    );

    let response = server.handle(request).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.questions.is_empty());
    {
        let snapshots = persistence.snapshots.lock().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert!(snapshots[0].iter().any(|record| {
            record.name.eq_dns(&added_name) && record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 9))
        }));
        assert!(
            !snapshots[0]
                .iter()
                .any(|record| record.name.eq_dns(&name(&["www", "example"])))
        );
        assert!(
            snapshots[0]
                .iter()
                .any(|record| { matches!(record.rdata, RData::SOA { serial: 2, .. }) })
        );
    }

    let lookup = Message::builder()
        .questions([Question {
            qname: added_name,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let lookup_response = server.handle(lookup).await;
    assert_eq!(lookup_response.headers.rcode, RCode::Ok);
    assert_eq!(lookup_response.answers.len(), 1);
}

#[tokio::test]
async fn dynamic_update_returns_each_prerequisite_failure_code() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let server = update_server(persistence);
    server.install(test_zone()).await.unwrap();
    let existing = name(&["www", "example"]);
    let missing = name(&["missing", "example"]);

    for (prerequisite, expected) in [
        (
            update_meta(missing.clone(), RecordType::Unknown(255), 255),
            RCode::NameError,
        ),
        (
            update_meta(missing.clone(), RecordType::A, 255),
            RCode::NXRRSet,
        ),
        (
            update_meta(existing.clone(), RecordType::Unknown(255), 254),
            RCode::YXDomain,
        ),
        (
            update_meta(existing.clone(), RecordType::A, 254),
            RCode::YXRRSet,
        ),
        (
            ResourceRecord {
                name: existing.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 0,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 200)),
            },
            RCode::NXRRSet,
        ),
    ] {
        let response = server.handle(update_request([prerequisite], [])).await;
        assert_eq!(response.headers.rcode, expected);
    }

    let exact_value = ResourceRecord {
        name: existing,
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    assert_eq!(
        server
            .handle(update_request([exact_value], []))
            .await
            .headers
            .rcode,
        RCode::Ok
    );
}

#[tokio::test]
async fn dynamic_update_distinguishes_notauth_notzone_and_formerr_processing_stages() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let server = update_server(persistence);
    server.install(test_zone()).await.unwrap();

    let mut unknown_zone = update_request([], []);
    unknown_zone.questions[0].qname = name(&["unknown"]);
    assert_eq!(
        server.handle(unknown_zone).await.headers.rcode,
        RCode::NotAuthoritative
    );

    let mut outside = update_request(
        [update_meta(
            name(&["inside", "example"]),
            RecordType::Unknown(255),
            255,
        )],
        [],
    );
    outside.answers[0].name = name(&["outside"]);
    assert_eq!(server.handle(outside).await.headers.rcode, RCode::NotZone);

    let mut malformed = update_request(
        [update_meta(name(&["www", "example"]), RecordType::A, 255)],
        [],
    );
    malformed.answers[0].ttl = 1;
    assert_eq!(
        server.handle(malformed).await.headers.rcode,
        RCode::FormatError
    );
}

#[tokio::test]
async fn dynamic_update_ignores_nonzero_reserved_header_bits() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let server = update_server(persistence);
    server.install(test_zone()).await.unwrap();
    let mut request = update_request([], []);
    request.headers.aa = true;
    request.headers.tc = true;
    request.headers.rd = true;
    request.headers.ra = true;
    request.headers.ad = true;
    request.headers.cd = true;
    request.headers.rcode = RCode::NameError;

    assert_eq!(server.handle(request).await.headers.rcode, RCode::Ok);
}

#[tokio::test]
async fn dynamic_update_applies_delete_name_delete_rrset_and_delete_record_in_order() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let server = update_server(Arc::clone(&persistence));
    server.install(test_zone()).await.unwrap();
    let multi = name(&["multi", "example"]);
    let first = Ipv4Addr::new(192, 0, 2, 20);
    let second = Ipv4Addr::new(192, 0, 2, 21);
    let mut delete_first = record(multi.clone(), RecordType::A, RData::A(first));
    delete_first.class = ClassType::Unknown(254);
    delete_first.ttl = 0;

    let response = server
        .handle(update_request(
            [],
            [
                record(multi.clone(), RecordType::A, RData::A(first)),
                record(multi.clone(), RecordType::A, RData::A(second)),
                delete_first,
                update_meta(name(&["www", "example"]), RecordType::A, 255),
                update_meta(name(&["alias", "example"]), RecordType::Unknown(255), 255),
                update_meta(name(&["example"]), RecordType::Unknown(255), 255),
            ],
        ))
        .await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    let snapshots = persistence.snapshots.lock().unwrap();
    let snapshot = snapshots.last().unwrap();
    assert!(
        snapshot
            .iter()
            .any(|record| { record.name.eq_dns(&multi) && record.rdata == RData::A(second) })
    );
    assert!(
        !snapshot
            .iter()
            .any(|record| record.name.eq_dns(&multi) && record.rdata == RData::A(first))
    );
    assert!(!snapshot.iter().any(|record| {
        record.name.eq_dns(&name(&["www", "example"]))
            || record.name.eq_dns(&name(&["alias", "example"]))
    }));
    assert!(snapshot.iter().any(|record| {
        record.name.eq_dns(&name(&["example"])) && record.rtype == RecordType::SOA
    }));
    assert!(snapshot.iter().any(|record| {
        record.name.eq_dns(&name(&["example"])) && record.rtype == RecordType::NS
    }));
}

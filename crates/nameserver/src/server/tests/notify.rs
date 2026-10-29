use super::*;

#[tokio::test]
async fn dynamic_update_uses_rfc1982_for_explicit_and_automatic_soa_serials() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let server = update_server(Arc::clone(&persistence));
    server.install(test_zone()).await.unwrap();
    let soa = |serial| {
        record(
            name(&["example"]),
            RecordType::SOA,
            RData::SOA {
                mname: name(&["primary", "invalid"]),
                rname: DomainName::root(),
                serial,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 300,
            },
        )
    };

    let ignored_equal = server
        .handle(update_request(
            [],
            [
                soa(1),
                record(
                    name(&["changed", "example"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 30)),
                ),
            ],
        ))
        .await;
    assert_eq!(ignored_equal.headers.rcode, RCode::Ok);
    assert!(
        persistence.snapshots.lock().unwrap()[0]
            .iter()
            .any(|record| matches!(record.rdata, RData::SOA { serial: 2, .. }))
    );

    let accepted_higher = server.handle(update_request([], [soa(10)])).await;
    assert_eq!(accepted_higher.headers.rcode, RCode::Ok);
    assert!(
        persistence.snapshots.lock().unwrap()[1]
            .iter()
            .any(|record| matches!(record.rdata, RData::SOA { serial: 10, .. }))
    );
}

#[tokio::test]
async fn changed_primary_snapshots_emit_one_rfc1996_notify_per_unique_target() {
    let transport = RecordingNotifyTransport::new(0, RCode::Ok);
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 5301));
    let other_zone = name(&["other"]);
    let notify = NotifyConfig::new(
        transport.clone(),
        [
            NotifyTarget::new(name(&["example"]), ClassType::IN, target),
            NotifyTarget::new(name(&["EXAMPLE"]), ClassType::IN, target),
            NotifyTarget::new(other_zone, ClassType::IN, target),
        ],
    )
    .with_retry_policy(Duration::from_millis(5), NonZeroU8::new(2).unwrap());
    let server = NameServer::with_config(NameServerConfig {
        notify: Some(notify),
        ..NameServerConfig::default()
    });

    server.install(test_zone_with_serial(1)).await.unwrap();
    server.install(test_zone_with_serial(1)).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), transport.wait_for_calls(1))
            .await
            .is_err()
    );

    server.install(test_zone_with_serial(2)).await.unwrap();
    transport.wait_for_calls(1).await;
    let calls = transport.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, target);
    let request = &calls[0].1;
    assert_eq!(request.headers.opcode, OpCode::Notify);
    assert!(request.headers.aa && !request.headers.qr);
    assert!(matches!(
        request.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::SOA { serial: 2, .. },
            ..
        }]
    ));
}

#[tokio::test]
async fn repeated_zone_changes_coalesce_behind_one_notify_task() {
    let transport = BlockingNotifyTransport::default();
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 5306));
    let notify = NotifyConfig::new(
        transport.clone(),
        [NotifyTarget::new(name(&["example"]), ClassType::IN, target)],
    )
    .with_retry_policy(Duration::from_millis(1), NonZeroU8::new(1).unwrap());
    let server = NameServer::with_config(NameServerConfig {
        notify: Some(notify),
        ..NameServerConfig::default()
    });
    server.install(test_zone_with_serial(1)).await.unwrap();
    server.install(test_zone_with_serial(2)).await.unwrap();
    transport.wait_for_calls(1).await;

    for serial in 3..=100 {
        server.install(test_zone_with_serial(serial)).await.unwrap();
    }

    assert_eq!(transport.calls().len(), 1);
    let tasks = server.notify_tasks.lock().await;
    assert_eq!(tasks.len(), 1);
    let pending = tasks.values().next().and_then(Option::as_ref).unwrap();
    assert!(matches!(
        pending.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::SOA { serial: 100, .. },
            ..
        }]
    ));
}

#[tokio::test]
async fn notify_retries_with_one_id_and_stops_after_a_matching_response() {
    let transport = RecordingNotifyTransport::new(2, RCode::Ok);
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 5302));
    let notify = NotifyConfig::new(
        transport.clone(),
        [NotifyTarget::new(name(&["example"]), ClassType::IN, target)],
    )
    .with_retry_policy(Duration::from_millis(1), NonZeroU8::new(3).unwrap());
    let server = NameServer::with_config(NameServerConfig {
        notify: Some(notify),
        ..NameServerConfig::default()
    });
    server.install(test_zone_with_serial(1)).await.unwrap();
    server.install(test_zone_with_serial(2)).await.unwrap();

    transport.wait_for_calls(3).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let calls = transport.calls();
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|(server, _)| *server == target));
    assert!(
        calls
            .iter()
            .all(|(_, request)| request.headers.id == calls[0].1.headers.id)
    );
}

#[tokio::test]
async fn notify_treats_notimp_as_terminal() {
    let transport = RecordingNotifyTransport::new(0, RCode::NotImplemented);
    let notify = NotifyConfig::new(
        transport.clone(),
        [NotifyTarget::new(
            name(&["example"]),
            ClassType::IN,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5303)),
        )],
    )
    .with_retry_policy(Duration::from_millis(1), NonZeroU8::new(3).unwrap());
    let server = NameServer::with_config(NameServerConfig {
        notify: Some(notify),
        ..NameServerConfig::default()
    });
    server.install(test_zone_with_serial(1)).await.unwrap();
    server.install(test_zone_with_serial(2)).await.unwrap();

    transport.wait_for_calls(1).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(transport.calls().len(), 1);
}

#[tokio::test]
async fn notify_sends_once_over_tcp_even_when_udp_retries_are_configured() {
    let transport = RecordingNotifyTransport::with_protocol(
        usize::MAX,
        RCode::Ok,
        Some(TransportProtocol::Tcp),
    );
    let notify = NotifyConfig::new(
        transport.clone(),
        [NotifyTarget::new(
            name(&["example"]),
            ClassType::IN,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5305)),
        )],
    )
    .with_retry_policy(Duration::from_millis(1), NonZeroU8::new(3).unwrap());
    let server = NameServer::with_config(NameServerConfig {
        notify: Some(notify),
        ..NameServerConfig::default()
    });
    server.install(test_zone_with_serial(1)).await.unwrap();
    server.install(test_zone_with_serial(2)).await.unwrap();

    transport.wait_for_calls(1).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(transport.calls().len(), 1);
}

#[tokio::test]
async fn committed_dynamic_update_notifies_only_after_durable_persistence() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let transport = RecordingNotifyTransport::new(0, RCode::Ok);
    let notify = NotifyConfig::new(
        transport.clone(),
        [NotifyTarget::new(
            name(&["example"]),
            ClassType::IN,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5304)),
        )],
    )
    .with_retry_policy(Duration::from_millis(5), NonZeroU8::new(1).unwrap());
    let server = NameServer::with_config(NameServerConfig {
        update_persistence: Some(persistence.clone()),
        allow_insecure_updates: true,
        notify: Some(notify),
        ..NameServerConfig::default()
    });
    server.install(test_zone()).await.unwrap();

    let response = server
        .handle(update_request(
            [],
            [record(
                name(&["new", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 99)),
            )],
        ))
        .await;
    assert_eq!(response.headers.rcode, RCode::Ok);
    transport.wait_for_calls(1).await;
    assert_eq!(persistence.snapshots.lock().unwrap().len(), 1);
    assert!(matches!(
        transport.calls()[0].1.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::SOA { serial: 2, .. },
            ..
        }]
    ));
}

#[tokio::test]
async fn a_primary_without_a_secondary_role_returns_terminal_notimp_to_notify() {
    let server = NameServer::new();
    let response = server.handle(notify_request()).await;

    assert_eq!(response.headers.opcode, OpCode::Notify);
    assert_eq!(response.headers.rcode, RCode::NotImplemented);
    assert!(response.headers.qr);
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn a_persistence_failure_rolls_back_the_whole_dynamic_update() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    persistence.fail.store(true, Ordering::SeqCst);
    let server = update_server(Arc::clone(&persistence));
    server.install(test_zone()).await.unwrap();
    let added_name = name(&["uncommitted", "example"]);

    let response = server
        .handle(update_request(
            [],
            [record(
                added_name.clone(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 10)),
            )],
        ))
        .await;

    assert_eq!(response.headers.rcode, RCode::ServerFailure);
    let lookup = Message::builder()
        .questions([Question {
            qname: added_name,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    assert_eq!(server.handle(lookup).await.headers.rcode, RCode::NameError);
    assert!(persistence.snapshots.lock().unwrap().is_empty());
}

use super::*;
use transport::DnsRequestHandler;

fn immediate(server: &NameServer, query: &Message) -> Option<Message> {
    server.try_handle(
        query,
        &[],
        (Ipv4Addr::LOCALHOST, 1234).into(),
        TransportProtocol::Udp,
    )
}

#[tokio::test]
async fn immediate_authority_preserves_signed_data_flags_aliases_and_denials() {
    let server = NameServer::new();
    let exact = name(&["www", "example"]);
    let wildcard = name(&["*", "wild", "example"]);
    let alias = name(&["alias", "example"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    exact.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 80)),
                ),
                rrsig(exact.clone(), RecordType::A, 2),
                record(
                    wildcard.clone(),
                    RecordType::TXT,
                    RData::TXT(vec![b"wild".to_vec()]),
                ),
                rrsig(wildcard, RecordType::TXT, 2),
                record(
                    alias.clone(),
                    RecordType::CNAME,
                    RData::CNAME(exact.clone()),
                ),
                rrsig(alias.clone(), RecordType::CNAME, 2),
            ],
        ))
        .await
        .unwrap();
    for (owner, qtype) in [
        (exact.clone(), QueryType::A),
        (exact, QueryType::MX),
        (name(&["m", "wild", "example"]), QueryType::TXT),
        (name(&["m", "wild", "example"]), QueryType::A),
        (name(&["missing", "example"]), QueryType::A),
        (alias, QueryType::A),
    ] {
        for bits in 0..16 {
            let mut query = query_with_do(owner.clone(), qtype, bits & 1 != 0);
            query.headers.rd = bits & 2 != 0;
            query.headers.cd = bits & 4 != 0;
            query.headers.ad = bits & 8 != 0;
            let ready = immediate(&server, &query).unwrap();
            let ordinary = server.handle(query).await;
            assert_eq!(ready.into_wire().unwrap(), ordinary.into_wire().unwrap());
        }
    }
}

#[tokio::test]
async fn immediate_authority_defers_transaction_authentication_and_special_operations() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let now = unix_time_now();
    let mut tsig = tsig_query(42);
    TsigKey::new(
        name(&["key", "example"]),
        TsigAlgorithm::HmacSha256,
        vec![7; 32],
    )
    .unwrap()
    .sign_request(&mut tsig, now, 300, None)
    .unwrap();
    assert!(immediate(&server, &tsig).is_none());
    tsig.additionals.push(dns::Edns::default().into_record());
    assert!(immediate(&server, &tsig).is_none());
    let mut signed = tsig_query(42);
    test_sig0_key()
        .sign_request(&mut signed, now as u32 - 60, now as u32 + 60)
        .unwrap();
    assert!(immediate(&server, &signed).is_none());
    signed.additionals.push(dns::Edns::default().into_record());
    assert!(immediate(&server, &signed).is_none());
    for qtype in [QueryType::AXFR, QueryType::IXFR] {
        let mut transfer = tsig_query(42);
        transfer.questions[0].qtype = qtype;
        assert!(immediate(&server, &transfer).is_none());
    }
    let mut query = tsig_query(42);
    query.headers.opcode = dns::OpCode::Update;
    assert!(immediate(&server, &query).is_none());
    query.headers.opcode = dns::OpCode::Notify;
    assert!(immediate(&server, &query).is_none());
    query.headers.opcode = dns::OpCode::Query;
    query.additionals.push(
        dns::Edns {
            version: 1,
            ..dns::Edns::default()
        }
        .into_record(),
    );
    assert!(immediate(&server, &query).is_none());
}

#[tokio::test]
async fn immediate_authority_respects_a_queued_zone_writer() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = tsig_query(42);
    let read = server.zones.read().await.unwrap();
    let entered = Arc::new(Notify::new());
    let writer_entered = Arc::clone(&entered);
    let writer_server = server.clone();
    let writer = tokio::spawn(async move {
        writer_entered.notify_one();
        let _write = writer_server.zones.write().await;
    });
    entered.notified().await;
    assert!(immediate(&server, &query).is_none());
    assert!(
        server
            .try_handle_udp(&query, &[], (Ipv4Addr::LOCALHOST, 1234).into(), 1232)
            .is_none()
    );
    drop(read);
    writer.await.unwrap();
    assert!(immediate(&server, &query).is_some());
    assert!(
        server
            .try_handle_udp(&query, &[], (Ipv4Addr::LOCALHOST, 1234).into(), 1232)
            .is_some()
    );
}

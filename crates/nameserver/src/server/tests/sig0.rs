use super::*;

#[tokio::test]
async fn loopback_tcp_authenticates_sig0_and_binds_the_signed_response_to_the_query() {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_sig0_key();
    let server = NameServer::with_config(NameServerConfig {
        sig0_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    server.install(test_zone()).await.unwrap();
    let listener = tokio::spawn(TcpTransport.serve(address, server));

    let now = sig0::unix_time_now();
    let mut query = tsig_query(0x2931);
    key.sign_request(
        &mut query,
        (now as u32).wrapping_sub(60),
        (now as u32).wrapping_add(60),
    )
    .unwrap();
    let query_wire = query.into_wire().unwrap();
    let response_wire = raw_tcp_exchange(address, &query_wire).await;
    listener.abort();

    let verified = key
        .verification_key()
        .verify_response(&response_wire, &query_wire, now)
        .unwrap();
    assert_eq!(verified.message.headers.rcode, RCode::Ok);
    assert!(verified.message.headers.aa);
    assert!(matches!(
        verified.message.answers.as_slice(),
        [ResourceRecord {
            rtype: RecordType::A,
            rdata: RData::A(address),
            ..
        }] if *address == Ipv4Addr::new(192, 0, 2, 1)
    ));
}

#[tokio::test]
async fn sig0_rejects_an_exact_request_replay() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_sig0_key();
    let server = NameServer::with_config(NameServerConfig {
        sig0_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    let listener = tokio::spawn(UdpTransport.serve(address, server));

    let now = sig0::unix_time_now();
    let mut query = tsig_query(0x2932);
    key.sign_request(
        &mut query,
        (now as u32).wrapping_sub(60),
        (now as u32).wrapping_add(60),
    )
    .unwrap();
    let query_wire = query.into_wire().unwrap();
    let first = raw_udp_exchange(address, &query_wire).await;
    key.verification_key()
        .verify_response(&first, &query_wire, now)
        .unwrap();
    let replay = raw_udp_exchange(address, &query_wire).await;
    listener.abort();

    let replay = Message::from_wire(&replay).unwrap();
    assert_eq!(replay.headers.rcode, RCode::NotAuthoritative);
    assert!(
        !replay
            .additionals
            .iter()
            .any(|record| matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0()))
    );
}

#[tokio::test]
async fn sig0_rejects_a_request_with_excessive_future_validity() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_sig0_key();
    let server = NameServer::with_config(NameServerConfig {
        sig0_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    let listener = tokio::spawn(UdpTransport.serve(address, server));

    let now = sig0::unix_time_now();
    let mut query = tsig_query(0x2933);
    key.sign_request(&mut query, now as u32, (now as u32).wrapping_add(86_400))
        .unwrap();
    let response = raw_udp_exchange(address, &query.into_wire().unwrap()).await;
    listener.abort();

    let response = Message::from_wire(&response).unwrap();
    assert_eq!(response.headers.rcode, RCode::NotAuthoritative);
    assert!(
        !response
            .additionals
            .iter()
            .any(|record| matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0()))
    );
}

#[test]
fn sig0_replay_cache_fails_closed_at_its_capacity_and_prunes_expired_entries() {
    let principal = dns_name_key(&name(&["host", "example"]));
    let mut replays = Sig0ReplayCache::new();
    for index in 0..MAX_SIG0_REPLAYS_PER_PRINCIPAL {
        assert!(remember_sig0_request(
            &mut replays,
            principal.clone(),
            index.to_be_bytes().to_vec(),
            200,
            100,
        ));
    }
    assert_eq!(replays[&principal].len(), MAX_SIG0_REPLAYS_PER_PRINCIPAL);
    assert!(!remember_sig0_request(
        &mut replays,
        principal.clone(),
        b"overflow".to_vec(),
        200,
        100,
    ));
    assert!(!remember_sig0_request(
        &mut replays,
        principal.clone(),
        0_usize.to_be_bytes().to_vec(),
        200,
        100,
    ));

    let other = dns_name_key(&name(&["other", "example"]));
    assert!(remember_sig0_request(
        &mut replays,
        other.clone(),
        b"not-starved".to_vec(),
        200,
        100,
    ));
    assert_eq!(replays[&other].len(), 1);

    assert!(remember_sig0_request(
        &mut replays,
        principal.clone(),
        b"after-expiration".to_vec(),
        300,
        201,
    ));
    assert_eq!(replays[&principal].len(), 1);
    assert!(!replays.contains_key(&other));
}

#[test]
fn sig0_validity_window_bounds_both_clock_directions() {
    let window = Duration::from_secs(300);
    assert!(sig0_time_is_acceptable(700, 1_300, 1_000, window));
    assert!(!sig0_time_is_acceptable(699, 1_300, 1_000, window));
    assert!(!sig0_time_is_acceptable(700, 1_301, 1_000, window));
    assert!(!sig0_time_is_acceptable(
        1_000,
        1_000_u32.wrapping_add(86_400),
        1_000,
        window,
    ));
}

#[tokio::test]
async fn oversized_sig0_udp_response_keeps_question_and_required_opt_with_tc() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_sig0_key();
    let server = NameServer::with_config(NameServerConfig {
        sig0_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    let owner = name(&["large", "example"]);
    let records = (0_u8..8)
        .map(|value| {
            record(
                owner.clone(),
                RecordType::TXT,
                RData::TXT(vec![vec![value; 100]]),
            )
        })
        .collect();
    server
        .install(make_zone(name(&["example"]), ClassType::IN, 300, records))
        .await
        .unwrap();
    let listener = tokio::spawn(UdpTransport.serve(address, server));
    let now = sig0::unix_time_now();
    for (index, dnssec_ok) in [None, Some(false), Some(true)].into_iter().enumerate() {
        let mut query = Message::builder()
            .headers(Headers {
                id: 0x2934 + index as u16,
                ..Headers::default()
            })
            .questions([Question {
                qname: owner.clone(),
                qtype: QueryType::TXT,
                qclass: QClassType::Class(ClassType::IN),
            }])
            .build()
            .unwrap();
        if let Some(dnssec_ok) = dnssec_ok {
            query.additionals.push(
                dns::Edns {
                    dnssec_ok,
                    ..dns::Edns::new(512)
                }
                .into_record(),
            );
        }
        let expected_question = query.questions.clone();
        key.sign_request(
            &mut query,
            (now as u32).wrapping_sub(60),
            (now as u32).wrapping_add(60),
        )
        .unwrap();
        let request_wire = query.into_wire().unwrap();
        let response = raw_udp_exchange(address, &request_wire).await;
        assert!(response.len() <= 512);
        let verified = key
            .verification_key()
            .verify_response(&response, &request_wire, now)
            .unwrap();
        assert!(verified.message.headers.tc);
        assert_eq!(verified.message.headers.rcode, RCode::Ok);
        assert_eq!(verified.message.questions.len(), expected_question.len());
        let question = &verified.message.questions[0];
        assert!(question.qname.eq_dns(&expected_question[0].qname));
        assert_eq!(question.qtype, expected_question[0].qtype);
        assert_eq!(question.qclass, expected_question[0].qclass);
        assert!(verified.message.answers.is_empty());
        assert!(verified.message.authorities.is_empty());
        let edns = verified.message.edns().unwrap();
        assert_eq!(edns.as_ref().map(|edns| edns.dnssec_ok), dnssec_ok);
        assert_eq!(
            verified.message.additionals.len(),
            usize::from(dnssec_ok.is_some())
        );
    }
    listener.abort();
}

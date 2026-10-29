use super::*;

#[tokio::test]
async fn secure_update_maps_tsig_principal_and_enforces_name_and_type_policy() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_tsig_key("updater");
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let permitted = name(&["permitted", "example"]);
    let server = NameServer::with_config(NameServerConfig {
        update_persistence: Some(persistence.clone()),
        tsig_keys: vec![key.clone()],
        update_rules: vec![UpdateRule {
            identity: UpdateIdentity::Tsig(key.name().clone()),
            zone: name(&["example"]),
            name: permitted.clone(),
            record_types: vec![RecordType::A],
            include_subdomains: false,
        }],
        ..NameServerConfig::default()
    });
    server.install(test_zone()).await.unwrap();
    let listener = tokio::spawn(UdpTransport.serve(address, server.clone()));
    let now = unix_time_now();

    let mut allowed = update_request(
        [],
        [record(
            permitted.clone(),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 55)),
        )],
    );
    let allowed_mac = key.sign_request(&mut allowed, now, 300, None).unwrap();
    let allowed_wire = raw_udp_exchange(address, &allowed.into_wire().unwrap()).await;
    let allowed = key
        .verify_response(&allowed_wire, &allowed_mac, now)
        .unwrap();
    assert_eq!(allowed.message.headers.rcode, RCode::Ok);
    assert_eq!(persistence.snapshots.lock().unwrap().len(), 1);

    let mut denied = update_request(
        [],
        [record(
            name(&["other", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 56)),
        )],
    );
    let denied_mac = key.sign_request(&mut denied, now, 300, None).unwrap();
    let denied_wire = raw_udp_exchange(address, &denied.into_wire().unwrap()).await;
    listener.abort();
    let denied = key.verify_response(&denied_wire, &denied_mac, now).unwrap();
    assert_eq!(denied.message.headers.rcode, RCode::Refused);
    assert_eq!(persistence.snapshots.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn tcp_axfr_signs_every_message_with_a_running_tsig_mac() {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_tsig_key("transfer-key");
    let server = NameServer::with_config(NameServerConfig {
        allow_axfr_to: vec![(
            Ipv4Addr::LOCALHOST.into(),
            Ipv4Addr::new(255, 255, 255, 255).into(),
        )],
        tsig_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    let owner = name(&["bulk", "example"]);
    let records = (0_u16..700)
        .map(|value| {
            let mut text = value.to_be_bytes().to_vec();
            text.extend([b'x'; 98]);
            record(owner.clone(), RecordType::TXT, RData::TXT(vec![text]))
        })
        .collect();
    server
        .install(make_zone(name(&["example"]), ClassType::IN, 300, records))
        .await
        .unwrap();
    let listener = tokio::spawn(TcpTransport.serve(address, server));

    let now = unix_time_now();
    let mut query = Message::builder()
        .headers(Headers {
            id: 0x8954,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let request_mac = key.sign_request(&mut query, now, 300, None).unwrap();
    let wire_query = query.into_wire().unwrap();
    let mut stream = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(stream) = TcpStream::connect(address).await {
                return stream;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stream.write_u16(wire_query.len() as u16).await.unwrap();
    stream.write_all(&wire_query).await.unwrap();

    let mut frames = Vec::new();
    let mut soa_count = 0;
    while soa_count < 2 {
        let length = tokio::time::timeout(Duration::from_secs(1), stream.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut frame = vec![0; usize::from(length)];
        stream.read_exact(&mut frame).await.unwrap();
        let message = Message::from_wire(&frame).unwrap();
        soa_count += message
            .answers
            .iter()
            .filter(|record| record.rtype == RecordType::SOA)
            .count();
        frames.push(frame);
    }
    listener.abort();

    assert!(frames.len() > 1);
    let final_index = frames.len() - 1;
    let mut verifier = TsigStreamVerifier::new(key, request_mac);
    let mut message_count = 0;
    for (index, frame) in frames.iter().enumerate() {
        let batch = verifier
            .verify_next(frame, now, index == final_index)
            .unwrap()
            .unwrap();
        message_count += batch.messages.len();
    }
    assert_eq!(message_count, frames.len());
}

#[tokio::test]
async fn tsig_badkey_and_badsig_errors_are_unsigned() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let configured = test_tsig_key("configured-key");
    let server = NameServer::with_config(NameServerConfig {
        tsig_keys: vec![configured.clone()],
        ..NameServerConfig::default()
    });
    let listener = tokio::spawn(UdpTransport.serve(address, server));
    let now = unix_time_now();

    let unknown = test_tsig_key("unknown-key");
    let mut query = tsig_query(0x8947);
    let unknown_mac = unknown.sign_request(&mut query, now, 300, None).unwrap();
    let response = raw_udp_exchange(address, &query.into_wire().unwrap()).await;
    assert_eq!(
        unknown
            .verify_response(&response, &unknown_mac, now)
            .unwrap_err(),
        TsigAuthenticationError::UnsignedError {
            error: TsigErrorCode::BadKey
        }
    );

    let mut query = tsig_query(0x8948);
    let request_mac = configured.sign_request(&mut query, now, 300, None).unwrap();
    let mut wire = query.into_wire().unwrap();
    let qname_octet = wire.windows(3).position(|bytes| bytes == b"www").unwrap();
    wire[qname_octet] = b'x';
    let response = raw_udp_exchange(address, &wire).await;
    listener.abort();
    assert_eq!(
        configured
            .verify_response(&response, &request_mac, now)
            .unwrap_err(),
        TsigAuthenticationError::UnsignedError {
            error: TsigErrorCode::BadSignature
        }
    );
}

#[tokio::test]
async fn tsig_badtime_error_is_signed_and_reports_server_time() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_tsig_key("configured-key");
    let server = NameServer::with_config(NameServerConfig {
        tsig_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    let listener = tokio::spawn(UdpTransport.serve(address, server));

    let server_time = unix_time_now();
    let client_time = server_time.saturating_sub(1_000);
    let mut query = tsig_query(0x8949);
    let request_mac = key.sign_request(&mut query, client_time, 1, None).unwrap();
    let response = raw_udp_exchange(address, &query.into_wire().unwrap()).await;
    listener.abort();

    let verified = key
        .verify_response(&response, &request_mac, client_time)
        .unwrap();
    assert_eq!(verified.message.headers.rcode, RCode::NotAuthoritative);
    assert_eq!(verified.tsig.error, TsigErrorCode::BadTime);
    assert!(
        verified
            .tsig
            .bad_time_server_time()
            .is_some_and(|reported| reported >= server_time)
    );
}

#[tokio::test]
async fn tsig_badtrunc_error_is_signed_after_the_mac_validates() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let client_key = test_tsig_key("configured-key");
    let server_key = client_key.clone().with_minimum_mac_len(24).unwrap();
    let server = NameServer::with_config(NameServerConfig {
        tsig_keys: vec![server_key],
        ..NameServerConfig::default()
    });
    let listener = tokio::spawn(UdpTransport.serve(address, server));

    let now = unix_time_now();
    let mut query = tsig_query(0x8950);
    let request_mac = client_key
        .sign_request(&mut query, now, 300, Some(16))
        .unwrap();
    let response = raw_udp_exchange(address, &query.into_wire().unwrap()).await;
    listener.abort();

    let verified = client_key
        .verify_response(&response, &request_mac, now)
        .unwrap();
    assert_eq!(verified.message.headers.rcode, RCode::NotAuthoritative);
    assert_eq!(verified.tsig.error, TsigErrorCode::BadTruncation);
}

#[tokio::test]
async fn tsig_rejects_a_later_request_with_an_earlier_time_signed() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_tsig_key("configured-key");
    let server = NameServer::with_config(NameServerConfig {
        tsig_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    let listener = tokio::spawn(UdpTransport.serve(address, server));
    let now = unix_time_now();

    let mut first = tsig_query(0x8951);
    key.sign_request(&mut first, now, 300, None).unwrap();
    let _ = raw_udp_exchange(address, &first.into_wire().unwrap()).await;

    let earlier = now.saturating_sub(1);
    let mut second = tsig_query(0x8952);
    let request_mac = key.sign_request(&mut second, earlier, 300, None).unwrap();
    let response = raw_udp_exchange(address, &second.into_wire().unwrap()).await;
    listener.abort();

    let verified = key
        .verify_response(&response, &request_mac, earlier)
        .unwrap();
    assert_eq!(verified.tsig.error, TsigErrorCode::BadTime);
    assert_eq!(verified.message.headers.rcode, RCode::NotAuthoritative);
}

#[tokio::test]
async fn oversized_tsig_udp_response_keeps_question_and_required_opt_with_tc() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_tsig_key("configured-key");
    let server = NameServer::with_config(NameServerConfig {
        tsig_keys: vec![key.clone()],
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

    let now = unix_time_now();
    for (index, dnssec_ok) in [None, Some(false), Some(true)].into_iter().enumerate() {
        let mut query = Message::builder()
            .headers(Headers {
                id: 0x8953 + index as u16,
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
        let request_mac = key.sign_request(&mut query, now, 300, None).unwrap();
        let expected_question = query.questions.clone();
        let response = raw_udp_exchange(address, &query.into_wire().unwrap()).await;
        assert!(response.len() <= 512);
        let verified = key.verify_response(&response, &request_mac, now).unwrap();
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

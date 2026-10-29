use super::*;

#[test]
fn endpoint_validation_rejects_non_https_path_material() {
    assert!(validate_path("dns-query").is_err());
    assert!(validate_path("/dns-query?dns=abc").is_err());
    assert!(validate_path("/dns-query").is_ok());
    assert!(validate_authority("").is_err());
    assert!(validate_authority("dns.example:443").is_ok());
}

#[test]
fn age_reduces_dns_ttls_without_corrupting_opt_fields() {
    let mut message = Message {
        headers: dns::Headers::default(),
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    message.answers.push(dns::ResourceRecord {
        name: dns::DomainName::from_labels(vec![b"example".to_vec()]).expect("valid name"),
        rtype: dns::RecordType::A,
        class: dns::ClassType::IN,
        ttl: 30,
        rdata: dns::RData::A([192, 0, 2, 1].into()),
    });
    message.additionals.push(dns::Edns::default().into_record());
    let opt_ttl = message.additionals[0].ttl;

    apply_age(&mut message, 12);

    assert_eq!(message.answers[0].ttl, 18);
    assert_eq!(message.additionals[0].ttl, opt_ttl);
}

#[test]
fn overflowing_age_saturates_and_expires_dns_ttl() {
    let mut message = query(1);
    message.answers.push(dns::ResourceRecord {
        name: dns::DomainName::from_dotted("example").unwrap(),
        rtype: dns::RecordType::A,
        class: dns::ClassType::IN,
        ttl: 30,
        rdata: dns::RData::A([192, 0, 2, 1].into()),
    });

    let age = parse_age(&header::HeaderValue::from_static("4294967296")).unwrap();
    assert_eq!(age, u32::MAX);
    apply_age(&mut message, age);
    assert_eq!(message.answers[0].ttl, 0);
}

#[test]
fn age_uses_the_first_comma_delimited_member() {
    assert_eq!(
        parse_age(&header::HeaderValue::from_static("12, 13")),
        Some(12)
    );
    assert_eq!(
        parse_age(&header::HeaderValue::from_static(" \t12\t , 13")),
        Some(12)
    );
}

#[test]
fn invalid_first_age_member_does_not_adopt_a_later_member() {
    for value in ["invalid, 13", ", 13", "-1, 13", " \t, 13"] {
        let value = header::HeaderValue::from_str(value).unwrap();
        assert_eq!(parse_age(&value), None, "unexpectedly accepted {value:?}");
    }
}

#[tokio::test]
async fn exchange_rejects_a_present_malformed_age_instead_of_preserving_ttl() {
    let mut response = query(0);
    response.headers.qr = true;
    response.answers.push(dns::ResourceRecord {
        name: dns::DomainName::from_dotted("example").unwrap(),
        rtype: dns::RecordType::A,
        class: dns::ClassType::IN,
        ttl: 30,
        rdata: dns::RData::A([192, 0, 2, 1].into()),
    });
    let (server, _, task) = one_http_response_server("not-a-number", response).await;

    let error = DohTransport::new(client_config(DohMethod::Post))
        .exchange(server, &query(17), Duration::from_secs(2))
        .await
        .unwrap_err();

    assert!(
        matches!(
            &error,
            TransportError::InvalidHttpProtocol("response Age header is malformed")
        ),
        "unexpected error: {error:?}"
    );
    task.await.unwrap();
}

fn answer(id: u16) -> Message {
    let mut response = query(id);
    response.headers.qr = true;
    response.answers.push(ResourceRecord {
        name: dns::DomainName::from_dotted("example").unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::A([192, 0, 2, 1].into()),
    });
    response
}

fn unix_time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn tsig_doh_disables_request_caching_and_preserves_age_signed_bytes() {
    let key = TsigKey::new(
        dns::DomainName::from_dotted("key.example").unwrap(),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let now = unix_time_now();
    let mut request = query(0x8945);
    let request_mac = key.sign_request(&mut request, now, 300, None).unwrap();
    let mut response = answer(request.headers.id);
    key.sign_response(
        &mut response,
        &request_mac,
        request.headers.id,
        now,
        300,
        TsigErrorCode::NoError,
        Vec::new(),
        None,
    )
    .unwrap();
    let (server, cache_control, task) = one_http_response_server("12", response).await;

    let response = DohTransport::new(client_config(DohMethod::Post))
        .exchange(server, &request, Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(cache_control.await.unwrap().unwrap(), "no-store, no-cache");
    assert_eq!(response.answers[0].ttl, 30);
    key.verify_response(&response.into_wire().unwrap(), &request_mac, now)
        .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn sig0_doh_disables_request_caching_and_preserves_age_signed_bytes() {
    const PKCS8: &[u8] = &[
        48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 156, 58, 61, 68, 60, 178, 171,
        104, 83, 159, 96, 163, 246, 190, 164, 46, 68, 164, 64, 34, 239, 214, 158, 122, 111, 82, 80,
        170, 50, 90, 126, 173, 129, 33, 0, 40, 191, 220, 61, 124, 212, 177, 148, 240, 248, 32, 200,
        38, 226, 202, 169, 240, 228, 175, 220, 162, 168, 147, 131, 122, 208, 184, 21, 228, 15, 161,
        31,
    ];
    let key = dns::Sig0SigningKey::from_ed25519_pkcs8(
        dns::DomainName::from_dotted("key.example").unwrap(),
        0,
        3,
        PKCS8,
    )
    .unwrap();
    let now = unix_time_now();
    let mut request = query(0x2931);
    key.sign_request(
        &mut request,
        (now as u32).wrapping_sub(60),
        (now as u32).wrapping_add(60),
    )
    .unwrap();
    let request_wire = request.clone().into_wire().unwrap();
    let mut response = answer(request.headers.id);
    key.sign_response(
        &mut response,
        &request_wire,
        (now as u32).wrapping_sub(60),
        (now as u32).wrapping_add(60),
    )
    .unwrap();
    let (server, cache_control, task) = one_http_response_server("12", response).await;

    let response = DohTransport::new(client_config(DohMethod::Post))
        .exchange(server, &request, Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(cache_control.await.unwrap().unwrap(), "no-store, no-cache");
    assert_eq!(response.answers[0].ttl, 30);
    key.verification_key()
        .verify_response(&response.into_wire().unwrap(), &request_wire, now)
        .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn doh_server_marks_transaction_authenticated_responses_no_store() {
    let key = TsigKey::new(
        dns::DomainName::from_dotted("key.example").unwrap(),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let mut request_message = query(0x8945);
    key.sign_request(&mut request_message, unix_time_now(), 300, None)
        .unwrap();
    let request_wire = request_message.into_wire().unwrap();
    let (server, task) = one_connection_server(|mut message: Message| async move {
        message.headers.qr = true;
        message
    })
    .await;
    let config = client_config(DohMethod::Post);
    let tcp = TcpStream::connect(server).await.unwrap();
    let tls = TlsConnector::from(Arc::clone(&config.tls))
        .connect(config.authentication_name, tcp)
        .await
        .unwrap();
    let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("https://localhost/dns-query")
        .header(header::CONTENT_TYPE, DOH_MEDIA_TYPE)
        .body(())
        .unwrap();
    let (response, mut request_body) = sender.send_request(request, false).unwrap();
    request_body
        .send_data(Bytes::from(request_wire), true)
        .unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store, no-cache"
    );
    task.abort();
}

#[test]
fn freshness_uses_the_smallest_answer_ttl() {
    let mut message = query(1);
    message.answers.clear();
    for ttl in [600, 30, 300] {
        message.answers.push(dns::ResourceRecord {
            name: dns::DomainName::from_labels(vec![b"example".to_vec()]).expect("valid name"),
            rtype: dns::RecordType::A,
            class: dns::ClassType::IN,
            ttl,
            rdata: dns::RData::A([192, 0, 2, 1].into()),
        });
    }
    assert_eq!(freshness_lifetime(&message), 30);
}

fn soa(ttl: u32, minimum: u32) -> dns::ResourceRecord {
    soa_for("example", dns::ClassType::IN, ttl, minimum)
}

#[tokio::test]
async fn age_expires_effective_negative_ttls_without_changing_soa_rdata() {
    for (rcode, alias) in [
        (dns::RCode::Ok, false),
        (dns::RCode::NameError, false),
        (dns::RCode::NameError, true),
        (dns::RCode::Ok, true),
    ] {
        for age in [12, 60, 100] {
            let mut request = query(17);
            if alias {
                request.questions[0].qname = dns::DomainName::from_dotted("alias.example").unwrap();
            }
            let mut response = query(0);
            response.questions.clone_from(&request.questions);
            response.headers.qr = true;
            response.headers.rcode = rcode;
            if alias {
                response.answers = vec![cname_for("alias.example", "missing.example", 300)];
            }
            response.authorities = vec![soa(600, 60)];
            let soa_rdata = response.authorities[0].rdata.clone();
            let age_header = match age {
                12 => "12",
                60 => "60",
                _ => "100",
            };
            let (server, _, task) = one_http_response_server(age_header, response).await;
            let response = DohTransport::new(client_config(DohMethod::Post))
                .exchange(server, &request, Duration::from_secs(2))
                .await
                .unwrap();

            assert_eq!(response.headers.id, 17);
            assert_eq!(response.authorities[0].ttl, 60_u32.saturating_sub(age));
            assert_eq!(freshness_lifetime(&response), 60_u32.saturating_sub(age));
            assert_eq!(response.authorities[0].rdata, soa_rdata);
            if alias {
                assert_eq!(response.answers[0].ttl, 300 - age);
            }
            task.abort();
        }
    }
}

#[test]
fn age_preserves_positive_soa_lifetimes_and_rdata() {
    let mut response = query(0);
    response.questions[0].qtype = QueryType::SOA;
    response.answers = vec![soa(600, 60)];
    response.authorities = vec![soa(600, 60)];
    let soa_rdata = response.answers[0].rdata.clone();

    apply_age(&mut response, 12);

    assert_eq!(response.answers[0].ttl, 588);
    assert_eq!(response.authorities[0].ttl, 588);
    assert_eq!(response.answers[0].rdata, soa_rdata);
    assert_eq!(response.authorities[0].rdata, soa_rdata);
}

fn soa_for(owner: &str, class: dns::ClassType, ttl: u32, minimum: u32) -> dns::ResourceRecord {
    dns::ResourceRecord {
        name: dns::DomainName::from_dotted(owner).expect("valid name"),
        rtype: dns::RecordType::SOA,
        class,
        ttl,
        rdata: dns::RData::SOA {
            mname: dns::DomainName::from_labels(vec![b"ns".to_vec(), b"example".to_vec()])
                .expect("valid name"),
            rname: dns::DomainName::from_labels(vec![b"hostmaster".to_vec(), b"example".to_vec()])
                .expect("valid name"),
            serial: 1,
            refresh: 60,
            retry: 60,
            expire: 60,
            minimum,
        },
    }
}

fn cname(ttl: u32) -> dns::ResourceRecord {
    cname_for("example", "missing.example", ttl)
}

fn cname_for(owner: &str, target: &str, ttl: u32) -> dns::ResourceRecord {
    dns::ResourceRecord {
        name: dns::DomainName::from_dotted(owner).expect("valid name"),
        rtype: dns::RecordType::CNAME,
        class: dns::ClassType::IN,
        ttl,
        rdata: dns::RData::CNAME(dns::DomainName::from_dotted(target).expect("valid name")),
    }
}

#[test]
fn negative_freshness_is_bounded_by_the_soa_ttl() {
    let mut message = query(1);
    message.answers.clear();
    message.authorities = vec![soa(30, 300), soa(600, 120)];

    assert_eq!(freshness_lifetime(&message), 30);
}

#[test]
fn negative_freshness_is_bounded_by_soa_minimum_regardless_of_order() {
    let mut message = query(1);
    message.answers.clear();
    message.authorities = vec![soa(600, 120), soa(300, 20)];

    assert_eq!(freshness_lifetime(&message), 20);
    message.authorities.reverse();
    assert_eq!(freshness_lifetime(&message), 20);
}

#[test]
fn cname_nxdomain_freshness_uses_answer_and_effective_negative_ttls() {
    let mut message = query(1);
    message.headers.rcode = dns::RCode::NameError;
    message.answers = vec![cname(15)];
    message.authorities = vec![soa(600, 20)];

    assert_eq!(freshness_lifetime(&message), 15);
}

#[test]
fn cname_nodata_freshness_uses_answer_and_every_effective_negative_ttl() {
    let mut message = query(1);
    message.answers = vec![cname(300)];
    message.authorities = vec![soa(40, 200), soa(600, 20)];

    assert_eq!(freshness_lifetime(&message), 20);
}

#[test]
fn negative_freshness_ignores_unrelated_soa_owner() {
    let mut message = query(1);
    message.answers.clear();
    message.authorities = vec![soa_for("other", dns::ClassType::IN, 30, 30)];

    assert_eq!(freshness_lifetime(&message), 0);
}

#[test]
fn negative_freshness_ignores_wrong_class_soa() {
    let mut message = query(1);
    message.answers.clear();
    message.authorities = vec![soa_for("example", dns::ClassType::CH, 30, 30)];

    assert_eq!(freshness_lifetime(&message), 0);
}

#[test]
fn empty_question_negative_freshness_is_zero() {
    let mut message = query(1);
    message.headers.rcode = dns::RCode::NameError;
    message.questions.clear();
    message.answers.clear();
    message.authorities = vec![soa(30, 30)];

    assert_eq!(freshness_lifetime(&message), 0);
}

#[test]
fn negative_freshness_applies_soa_to_cname_terminal_owner() {
    let mut message = query(1);
    message.questions[0].qname = dns::DomainName::from_dotted("alias.outside").unwrap();
    message.headers.rcode = dns::RCode::NameError;
    message.answers = vec![cname_for("alias.outside", "missing.example", 300)];
    message.authorities = vec![soa_for("example", dns::ClassType::IN, 80, 20)];

    assert_eq!(freshness_lifetime(&message), 20);
}

#[test]
fn negative_freshness_without_an_applicable_soa_is_zero() {
    let mut message = query(1);
    message.answers.clear();
    message.authorities.clear();

    assert_eq!(freshness_lifetime(&message), 0);
}

#[test]
fn multiple_negative_questions_use_smallest_applicable_soa_ttl() {
    let mut message = query(1);
    message.questions = vec![
        Question {
            qname: dns::DomainName::from_dotted("alias.example").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        },
        Question {
            qname: dns::DomainName::from_dotted("alias.other").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        },
    ];
    message.answers = vec![
        cname_for("alias.example", "missing.example", 300),
        cname_for("alias.other", "missing.other", 300),
    ];
    message.authorities = vec![
        soa_for("example", dns::ClassType::IN, 90, 90),
        soa_for("other", dns::ClassType::IN, 80, 20),
    ];

    assert_eq!(freshness_lifetime(&message), 20);
}

use super::*;

#[tokio::test]
async fn post_body_read_is_bounded_by_the_request_timeout() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    let (server, task) = one_connection_server_with_timeout(
        move |message: Message| {
            let calls = Arc::clone(&server_calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                message
            }
        },
        Duration::from_millis(20),
    )
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
    let (response, _body) = sender.send_request(request, false).unwrap();

    let response = time::timeout(Duration::from_secs(2), response)
        .await
        .expect("server should bound an incomplete POST body")
        .unwrap();

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test]
async fn post_authenticates_pads_and_reuses_one_http2_connection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    let (server, task) = one_connection_server(move |message: Message| {
        let calls = Arc::clone(&server_calls);
        async move {
            assert_eq!(message.headers.id, 0);
            calls.fetch_add(1, Ordering::SeqCst);
            message
        }
    })
    .await;
    let transport = DohTransport::new(client_config(DohMethod::Post));

    for id in [41, 42] {
        let response = transport
            .exchange(server, &query(id), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.headers.id, id);
        assert!(response.edns().unwrap().unwrap().padding().is_some());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn persistent_connection_keeps_retained_request_tasks_bounded() {
    let request_task_metrics = Arc::new(RequestTaskMetrics::default());
    let (server, task) = observed_one_connection_server(
        |message: Message| async move { message },
        Arc::clone(&request_task_metrics),
    )
    .await;
    let transport = DohTransport::new(client_config(DohMethod::Post));

    for id in 0..(MAX_CONCURRENT_REQUESTS as u16 * 4) {
        let response = transport
            .exchange(server, &query(id), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.headers.id, id);
    }

    time::timeout(Duration::from_secs(1), async {
        while request_task_metrics.retained.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed request tasks should be reaped while the connection remains idle");
    assert!(
        request_task_metrics.high_water.load(Ordering::SeqCst) <= MAX_CONCURRENT_REQUESTS,
        "completed request task records grew past the active-request admission bound"
    );
    task.abort();
}

#[tokio::test]
async fn saturated_connection_keeps_driving_admitted_request_bodies() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    let request_task_metrics = Arc::new(RequestTaskMetrics::default());
    let (server, task) = observed_one_connection_server(
        move |message: Message| {
            let calls = Arc::clone(&server_calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                message
            }
        },
        Arc::clone(&request_task_metrics),
    )
    .await;
    let config = client_config(DohMethod::Post);
    let tcp = TcpStream::connect(server).await.unwrap();
    let tls = TlsConnector::from(Arc::clone(&config.tls))
        .connect(config.authentication_name, tcp)
        .await
        .unwrap();
    let (sender, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut responses = Vec::with_capacity(MAX_CONCURRENT_REQUESTS);
    let mut request_bodies = Vec::with_capacity(MAX_CONCURRENT_REQUESTS);
    for _ in 0..MAX_CONCURRENT_REQUESTS {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/dns-query")
            .header(header::CONTENT_TYPE, DOH_MEDIA_TYPE)
            .body(())
            .unwrap();
        let mut ready = sender.clone().ready().await.unwrap();
        let (response, request_body) = ready.send_request(request, false).unwrap();
        responses.push(response);
        request_bodies.push(request_body);
    }

    time::timeout(Duration::from_secs(2), async {
        while request_task_metrics.retained.load(Ordering::SeqCst) != MAX_CONCURRENT_REQUESTS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server should admit requests up to its task limit");

    request_bodies[0]
        .send_data(Bytes::from(query(7).into_wire().unwrap()), true)
        .unwrap();
    let response = time::timeout(Duration::from_secs(2), &mut responses[0])
        .await
        .expect("a saturated connection should keep driving admitted body data")
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        request_task_metrics.high_water.load(Ordering::SeqCst) <= MAX_CONCURRENT_REQUESTS,
        "active request tasks exceeded the admission bound"
    );
    task.abort();
}

#[tokio::test]
async fn concurrent_cold_misses_share_one_http2_handshake() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    let (server, task) = one_connection_server(move |message: Message| {
        let calls = Arc::clone(&server_calls);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            message
        }
    })
    .await;
    let transport = DohTransport::new(client_config(DohMethod::Post));
    let mut exchanges = tokio::task::JoinSet::new();
    for id in 1..=8 {
        let transport = transport.clone();
        exchanges.spawn(async move {
            transport
                .exchange(server, &query(id), Duration::from_secs(2))
                .await
                .unwrap()
        });
    }
    while let Some(result) = exchanges.join_next().await {
        assert!(result.unwrap().headers.qr);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 8);
    task.abort();
}

#[tokio::test]
async fn get_uses_unpadded_base64url_and_returns_dns_wire_data() {
    let (server, task) = one_connection_server(|message: Message| async move { message }).await;
    let response = DohTransport::new(client_config(DohMethod::Get))
        .exchange(server, &query(73), Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(response.headers.id, 73);
    assert!(response.headers.qr);
    task.abort();
}

#[test]
fn authenticated_queries_are_not_rewritten_after_signing() {
    let mut signed = query(73);
    signed.additionals.push(dns::ResourceRecord {
        name: dns::DomainName::root(),
        rtype: dns::RecordType::TSIG,
        class: dns::ClassType::Unknown(255),
        ttl: 0,
        rdata: dns::RData::Unknown(Vec::new()),
    });

    let prepared = prepared_query(&signed).unwrap();

    assert_eq!(prepared.headers.id, 73);
    assert!(prepared.edns().unwrap().unwrap().padding().is_none());
}

#[tokio::test]
async fn stream_queries_ignore_the_edns_udp_size_up_to_the_dns_limit() {
    for (method, length) in [
        (DohMethod::Get, 4096),
        (DohMethod::Get, 65535),
        (DohMethod::Post, 65535),
    ] {
        let request = crate::tests::fixtures::query_with_wire_length(query(73), length);
        let (server, task) = one_connection_server(|message: Message| async move { message }).await;
        let response = DohTransport::new(client_config(method))
            .exchange(server, &request, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.headers.id, 73);
        assert_eq!(response.edns().unwrap().unwrap().udp_payload_size, 1232);
        assert!(!response.headers.tc);
        assert!(response.into_wire().unwrap().len() >= length);
        task.abort();
    }
}

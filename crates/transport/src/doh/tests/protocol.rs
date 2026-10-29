use super::*;

#[tokio::test]
async fn rejects_streamed_handler_replies_and_cancels_the_producer() {
    struct StreamingThenBuffered(Mutex<Option<tokio::sync::mpsc::Receiver<Message>>>);

    impl DnsRequestHandler for StreamingThenBuffered {
        fn handle<'a>(&'a self, request: crate::DnsRequest) -> crate::BoxFuture<'a, ()> {
            Box::pin(async move {
                if let Some(responses) = self.0.lock().unwrap().take() {
                    // Inject an invalid internal response to exercise the
                    // server's defense beyond respond_stream's public guard.
                    let _ = request.response.send(crate::DnsResponse::Stream(responses));
                } else {
                    let response = request.message().clone();
                    request.respond(response);
                }
            })
        }
    }

    let (producer, responses) = tokio::sync::mpsc::channel(1);
    let (server, task) =
        one_connection_server(StreamingThenBuffered(Mutex::new(Some(responses)))).await;
    let transport = DohTransport::new(client_config(DohMethod::Post));
    let session = transport
        .connect(server, time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();

    for expected in [StatusCode::INTERNAL_SERVER_ERROR, StatusCode::OK] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/dns-query")
            .header(header::CONTENT_TYPE, DOH_MEDIA_TYPE)
            .body(())
            .unwrap();
        let mut sender = session.as_ref().clone().ready().await.unwrap();
        let (response, mut body) = sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from(query(0).into_wire().unwrap()), true)
            .unwrap();
        let response = time::timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), expected);
        assert!(producer.is_closed());
    }

    task.abort();
}

#[tokio::test]
async fn rejects_invalid_http_mappings_before_dispatching_dns() {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use dns::DomainName;
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
    let session = transport
        .connect(server, time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let wire = query(0).into_wire().unwrap();
    let get = format!(
        "https://localhost/dns-query?dns={}",
        Base64UrlUnpadded::encode_string(&wire)
    );
    let mut cases = vec![
        (
            Method::POST,
            "https://localhost/other".to_owned(),
            DOH_MEDIA_TYPE,
            wire.clone(),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            "application/octet-stream",
            wire.clone(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            Method::POST,
            "http://localhost/dns-query".to_owned(),
            DOH_MEDIA_TYPE,
            wire.clone(),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            "https://localhost/dns-query".to_owned(),
            DOH_MEDIA_TYPE,
            wire.clone(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::GET,
            format!("{get}="),
            DOH_MEDIA_TYPE,
            Vec::new(),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::GET,
            format!("{get}&dns=duplicate"),
            DOH_MEDIA_TYPE,
            Vec::new(),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::GET,
            "https://localhost/dns-query?dns=AA".to_owned(),
            DOH_MEDIA_TYPE,
            Vec::new(),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            DOH_MEDIA_TYPE,
            vec![0; 65536],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ];
    // RFC 4648 canonical tail bits must be zero. Mutate only unused bits
    // in otherwise valid DNS queries: lenient decoding would dispatch them.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for prefix in ["a", "aa", "aaa"] {
        let mut valid = query(0);
        valid.questions[0].qname =
            DomainName::from_dotted(&format!("{prefix}.example.test.")).unwrap();
        let wire = valid.into_wire().unwrap();
        if wire.len().is_multiple_of(3) {
            continue;
        }
        let mut encoded = Base64UrlUnpadded::encode_string(&wire).into_bytes();
        let last = encoded.last_mut().unwrap();
        let index = alphabet.iter().position(|octet| octet == last).unwrap();
        *last = alphabet[index | 1];
        cases.push((
            Method::GET,
            format!(
                "https://localhost/dns-query?dns={}",
                String::from_utf8(encoded).unwrap()
            ),
            DOH_MEDIA_TYPE,
            Vec::new(),
            StatusCode::BAD_REQUEST,
        ));
    }
    for (method, uri, content_type, body, expected) in cases {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, content_type)
            .body(())
            .unwrap();
        let mut sender = session.as_ref().clone().ready().await.unwrap();
        let (response, mut stream) = sender.send_request(request, body.is_empty()).unwrap();
        if !body.is_empty() {
            stream.send_data(Bytes::from(body), true).unwrap();
        }
        let response = time::timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // Invalid HTTP requests do not poison other streams on the session.
    assert!(
        transport
            .exchange(server, &query(7), Duration::from_secs(2))
            .await
            .unwrap()
            .headers
            .qr
    );
    task.abort();
}

#[tokio::test]
async fn rejects_untrusted_certificates_wrong_names_and_incompatible_alpn() {
    for case in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config =
            DohServerConfig::new(vec![certificate()], private_key(), "/dns-query".to_owned())
                .unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            assert!(TlsAcceptor::from(config.tls).accept(tcp).await.is_err());
        });
        let mut config = client_config(DohMethod::Post);
        match case {
            0 => {
                config = DohClientConfig::new(
                    RootCertStore::empty(),
                    "localhost".to_owned(),
                    "localhost".to_owned(),
                    "/dns-query".to_owned(),
                    DohMethod::Post,
                )
                .unwrap()
            }
            1 => {
                config.authentication_name =
                    ServerName::try_from("wrong.example").unwrap().to_owned()
            }
            _ => Arc::make_mut(&mut config.tls).alpn_protocols = vec![b"dot".to_vec()],
        }
        assert!(
            DohTransport::new(config)
                .exchange(address, &query(7), Duration::from_secs(2))
                .await
                .is_err()
        );
        time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}

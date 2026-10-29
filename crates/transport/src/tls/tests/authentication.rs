use super::*;

#[tokio::test]
async fn rejects_a_certificate_for_the_wrong_authentication_name() {
    let (server, task) = one_connection_server(PaddedHandler {
        calls: Arc::new(AtomicUsize::new(0)),
    })
    .await;
    let transport = TlsTransport::new(client_config("wrong.example"));

    assert!(matches!(
        transport
            .exchange(server, &query(42), Duration::from_secs(2))
            .await,
        Err(TransportError::Io(_))
    ));
    task.abort();
}

#[tokio::test]
async fn supports_authorized_mutual_tls_for_xot() {
    let mut client_roots = RootCertStore::empty();
    client_roots.add(certificate()).unwrap();
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .unwrap();
    let server_config =
        TlsServerConfig::with_client_verifier(client_verifier, vec![certificate()], private_key())
            .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server_with_config(
        server_config,
        PaddedHandler {
            calls: Arc::clone(&calls),
        },
    )
    .await;
    let mut server_roots = RootCertStore::empty();
    server_roots.add(certificate()).unwrap();
    let client_config = TlsClientConfig::with_client_auth(
        server_roots,
        "localhost".to_owned(),
        vec![certificate()],
        private_key(),
    )
    .unwrap();

    TlsTransport::new(client_config)
        .exchange(server, &query(42), Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn rejects_an_xot_client_without_an_authorized_certificate() {
    let mut client_roots = RootCertStore::empty();
    client_roots.add(certificate()).unwrap();
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .unwrap();
    let server_config =
        TlsServerConfig::with_client_verifier(client_verifier, vec![certificate()], private_key())
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config.0);
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        assert!(acceptor.accept(stream).await.is_err());
    });

    assert!(matches!(
        TlsTransport::new(client_config("localhost"))
            .exchange(server, &query(42), Duration::from_secs(2))
            .await,
        Err(TransportError::Io(_))
    ));
    server_task.await.unwrap();
}

#[tokio::test]
async fn authenticates_an_rfc7250_raw_public_key_against_an_spki_pin() {
    let (resolver, expected_spki) = raw_public_key_resolver_and_pin();
    let server_config = TlsServerConfig::with_certificate_resolver(resolver).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server_with_config(
        server_config,
        PaddedHandler {
            calls: Arc::clone(&calls),
        },
    )
    .await;
    let verifier = Arc::new(RawPublicKeyPinVerifier { expected_spki });
    let client_config =
        TlsClientConfig::with_server_verifier(verifier, "localhost".to_owned()).unwrap();

    TlsTransport::new(client_config)
        .exchange(server, &query(42), Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn rejects_an_rfc7250_raw_public_key_outside_the_spki_pin_set() {
    let (resolver, mut expected_spki) = raw_public_key_resolver_and_pin();
    expected_spki[0] ^= 1;
    let server_config = TlsServerConfig::with_certificate_resolver(resolver).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config.0);
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        assert!(acceptor.accept(stream).await.is_err());
    });
    let verifier = Arc::new(RawPublicKeyPinVerifier { expected_spki });
    let client_config =
        TlsClientConfig::with_server_verifier(verifier, "localhost".to_owned()).unwrap();

    assert!(matches!(
        TlsTransport::new(client_config)
            .exchange(server, &query(42), Duration::from_secs(2))
            .await,
        Err(TransportError::Io(_))
    ));
    server_task.await.unwrap();
}

#[tokio::test]
async fn accepts_an_ordinary_dot_tls13_session_without_alpn() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config().0);
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        assert!(validate_server_session(&stream, false).is_ok());
        assert!(matches!(
            validate_server_session(&stream, true),
            Err(TransportError::InvalidTlsProtocol(_))
        ));
    });

    let mut roots = RootCertStore::empty();
    roots.add(certificate()).unwrap();
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let transport = TlsTransport::new(TlsClientConfig {
        config: Arc::new(config),
        authentication_name: ServerName::try_from("localhost".to_owned()).unwrap(),
    });

    // The server deliberately closes without answering. Reaching ordinary I/O
    // proves the client admitted TLS 1.3 with no negotiated ALPN.
    assert!(matches!(
        transport
            .exchange(server, &query(42), Duration::from_secs(2))
            .await,
        Err(TransportError::Io(_))
    ));
    server_task.await.unwrap();
}

#[test]
fn dot_alpn_policy_rejects_wrong_tokens_and_requires_alpn_for_xot() {
    assert!(validate_dot_alpn(Some(DOT_ALPN), false).is_ok());
    assert!(validate_dot_alpn(None, false).is_ok());
    assert!(validate_dot_alpn(Some(b"h2"), false).is_err());
    assert!(validate_dot_alpn(None, true).is_err());
}

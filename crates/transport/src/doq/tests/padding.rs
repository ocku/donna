use super::*;

use dns::{TsigAlgorithm, TsigErrorCode, TsigKey};
use tokio::net::UdpSocket;

struct SignedHandler(TsigKey);

impl DnsRequestHandler for SignedHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let now = unix_time();
            let verified = self.0.verify_request(request.wire_message(), now).unwrap();
            let mut response = request.message().clone();
            response.additionals.clear();
            response.headers.qr = true;
            self.0
                .sign_response(
                    &mut response,
                    &verified.mac,
                    0,
                    now,
                    300,
                    TsigErrorCode::NoError,
                    Vec::new(),
                    None,
                )
                .unwrap();
            assert!(request.respond(response));
        })
    }
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn packet_padding_covers_non_edns_and_signed_transactions() {
    for signed in [false, true] {
        let key = TsigKey::new(
            dns::DomainName::from_dotted("key.example").unwrap(),
            TsigAlgorithm::HmacSha256,
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let mut config = DoqServerConfig::new(vec![certificate()], private_key()).unwrap();
        // Fix the MTU so MTU-discovery probes cannot masquerade as padded
        // application packets observed by the forwarding socket below.
        Arc::get_mut(&mut config.0.transport)
            .unwrap()
            .mtu_discovery_config(None);
        let endpoint = Endpoint::server(config.0, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server = endpoint.local_addr().unwrap();
        let server_key = key.clone();
        let server_task = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
            if signed {
                serve_connection_with_stream_timeout(
                    incoming,
                    Arc::new(SignedHandler(server_key)),
                    permit,
                    HANDLER_TIMEOUT,
                )
                .await;
            } else {
                serve_connection_with_stream_timeout(
                    incoming,
                    Arc::new(EchoHandler(Arc::new(AtomicUsize::new(0)))),
                    permit,
                    HANDLER_TIMEOUT,
                )
                .await;
            }
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = socket.local_addr().unwrap();
        let datagrams = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&datagrams);
        let proxy_task = tokio::spawn(async move {
            let mut client = None;
            let mut buffer = vec![0; 65536];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let from_server = peer == server;
                // QUIC v1 short headers identify 1-RTT packets. Initial and
                // Handshake packets have their own mandatory padding rules.
                if length > 0 && buffer[0] & 0x80 == 0 {
                    observed.lock().unwrap().push((from_server, length));
                }
                let target = if from_server {
                    client.unwrap()
                } else {
                    client = Some(peer);
                    server
                };
                socket.send_to(&buffer[..length], target).await.unwrap();
            }
        });

        let mut config = client_config();
        let mut quic_transport = transport_config(0).unwrap();
        Arc::get_mut(&mut quic_transport)
            .unwrap()
            .mtu_discovery_config(None);
        config.quic.transport_config(quic_transport);
        let transport = DoqTransport::new(config);
        let mut request = query(0, QueryType::A);
        request.additionals.clear();
        let request_mac = signed.then(|| {
            key.sign_request(&mut request, unix_time(), 300, None)
                .unwrap()
        });
        // A second exchange also covers a reused connection after any
        // coalescing of the first response with the final handshake packets.
        for _ in 0..2 {
            let response = transport
                .exchange(proxy, &request, Duration::from_secs(2))
                .await
                .unwrap();
            assert!(response.edns().unwrap().is_none());
            if let Some(mac) = &request_mac {
                key.verify_response(&response.into_wire().unwrap(), mac, unix_time())
                    .unwrap();
            }
        }
        let datagrams = datagrams.lock().unwrap().clone();
        for from_server in [false, true] {
            assert!(
                datagrams.contains(&(from_server, 1200)),
                "missing padded 1-RTT packet: signed={signed}, from_server={from_server}, packets={datagrams:?}",
            );
        }
        proxy_task.abort();
        server_task.abort();
    }
}

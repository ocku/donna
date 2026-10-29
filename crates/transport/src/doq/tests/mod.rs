use super::config::transport_config;
use super::*;
use rustls::RootCertStore;
use std::sync::atomic::{AtomicUsize, Ordering};

use dns::{ClassType, Headers, QClassType, QueryType, Question, RData, RecordType, ResourceRecord};

use crate::{
    DnsRequest, DnsRequestHandler, TransportProtocol,
    tests::fixtures::{certificate, private_key},
};

fn client_config() -> DoqClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(certificate()).unwrap();
    DoqClientConfig::new(roots, "localhost".to_owned()).unwrap()
}

fn question(qtype: QueryType) -> Question {
    Question {
        qname: dns::DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        qtype,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn query(id: u16, qtype: QueryType) -> Message {
    Message::builder()
        .headers(Headers {
            id,
            ..Headers::default()
        })
        .questions([question(qtype)])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap()
}

async fn one_connection_server<H>(handler: H) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    H: DnsRequestHandler + 'static,
{
    one_connection_server_with_timeout(handler, HANDLER_TIMEOUT).await
}

async fn one_connection_server_with_timeout<H>(
    handler: H,
    stream_timeout: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    H: DnsRequestHandler + 'static,
{
    let config = DoqServerConfig::new(vec![certificate()], private_key()).unwrap();
    let endpoint = Endpoint::server(config.0, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        serve_connection_with_stream_timeout(incoming, Arc::new(handler), permit, stream_timeout)
            .await;
    });
    (address, task)
}

struct EchoHandler(Arc<AtomicUsize>);

impl DnsRequestHandler for EchoHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            assert_eq!(request.protocol(), TransportProtocol::Quic);
            assert_eq!(request.message().headers.id, 0);
            self.0.fetch_add(1, Ordering::SeqCst);
            let response = request.message().clone();
            assert!(request.respond(response));
        })
    }
}

struct TransferHandler;

impl DnsRequestHandler for TransferHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let soa = ResourceRecord {
                name: request.message().questions[0].qname.clone(),
                rtype: RecordType::SOA,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::SOA {
                    mname: dns::DomainName::root(),
                    rname: dns::DomainName::root(),
                    serial: 1,
                    refresh: 2,
                    retry: 3,
                    expire: 4,
                    minimum: 5,
                },
            };
            let response = Message {
                headers: Headers::default(),
                questions: Vec::new(),
                answers: vec![soa.clone(), soa],
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            assert!(request.respond(response));
        })
    }
}

struct BackpressuredHandler(Arc<AtomicUsize>);

impl DnsRequestHandler for BackpressuredHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            if request.message().questions[0].qtype != QueryType::AXFR {
                self.0.fetch_add(1, Ordering::SeqCst);
                let response = request.message().clone();
                assert!(request.respond(response));
                return;
            }

            let name = request.message().questions[0].qname.clone();
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            assert!(request.respond_stream(receiver));
            tokio::spawn(async move {
                let first = Message {
                    headers: Headers::default(),
                    questions: Vec::new(),
                    answers: vec![soa(name.clone())],
                    authorities: Vec::new(),
                    additionals: Vec::new(),
                };
                if sender.send(first).await.is_err() {
                    return;
                }
                let large_record = ResourceRecord {
                    name,
                    rtype: RecordType::Unknown(65_280),
                    class: ClassType::IN,
                    ttl: 60,
                    rdata: RData::Unknown(vec![0; 32 * 1024]),
                };
                loop {
                    let response = Message {
                        headers: Headers::default(),
                        questions: Vec::new(),
                        answers: vec![large_record.clone()],
                        authorities: Vec::new(),
                        additionals: Vec::new(),
                    };
                    if sender.send(response).await.is_err() {
                        return;
                    }
                }
            });
        })
    }
}

fn soa(name: dns::DomainName) -> ResourceRecord {
    ResourceRecord {
        name,
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::SOA {
            mname: dns::DomainName::root(),
            rname: dns::DomainName::root(),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        },
    }
}

#[test]
fn accepts_exactly_one_length_prefixed_dns_message() {
    assert_eq!(one_framed_message(&[0, 3, 1, 2, 3]), Ok(&[1, 2, 3][..]));
    assert!(one_framed_message(&[0, 2, 1]).is_err());
    assert!(one_framed_message(&[0, 1, 1, 2]).is_err());
    assert!(one_framed_message(&[0, 0]).is_err());
}

#[test]
fn rejects_port_53_and_does_not_rewrite_authenticated_queries() {
    assert!(reject_port_53("127.0.0.1:53".parse().unwrap()).is_err());

    let mut signed = query(0, QueryType::A);
    signed.additionals.push(dns::ResourceRecord {
        name: dns::DomainName::root(),
        rtype: dns::RecordType::TSIG,
        class: dns::ClassType::Unknown(255),
        ttl: 0,
        rdata: dns::RData::Unknown(Vec::new()),
    });
    let prepared = prepare_query(&signed).unwrap();
    assert_eq!(prepared.headers.id, 0);
    assert!(prepared.edns().unwrap().unwrap().padding().is_none());

    signed.headers.id = 1;
    assert!(prepare_query(&signed).is_err());
}

#[tokio::test]
async fn authenticates_zeros_ids_pads_and_reuses_the_quic_connection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server(EchoHandler(Arc::clone(&calls))).await;
    let transport = DoqTransport::new(client_config());

    for id in [41, 42] {
        let response = transport
            .exchange(server, &query(id, QueryType::A), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.headers.id, id);
        assert!(response.headers.qr);
        assert!(response.edns().unwrap().unwrap().padding().is_some());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn concurrent_cold_misses_share_one_quic_handshake() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server(EchoHandler(Arc::clone(&calls))).await;
    let transport = DoqTransport::new(client_config());
    let mut exchanges = tokio::task::JoinSet::new();
    for id in 1..=8 {
        let transport = transport.clone();
        exchanges.spawn(async move {
            transport
                .exchange(server, &query(id, QueryType::A), Duration::from_secs(2))
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
async fn transfers_axfr_as_multiple_framed_responses_on_one_stream() {
    let (server, task) = one_connection_server(TransferHandler).await;
    let records = DoqTransport::new(client_config())
        .transfer(server, &query(91, QueryType::AXFR), Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(records.len(), 2);
    assert!(records[0].name.eq_dns(&records[1].name));
    assert_eq!(records[0].rtype, records[1].rtype);
    assert_eq!(records[0].class, records[1].class);
    assert_eq!(records[0].rdata, records[1].rdata);
    task.abort();
}

#[tokio::test]
async fn slowloris_stream_times_out_without_closing_connection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server_with_timeout(
        EchoHandler(Arc::clone(&calls)),
        Duration::from_millis(100),
    )
    .await;
    let transport = DoqTransport::new(client_config());
    let deadline = time::Instant::now() + Duration::from_secs(2);
    let connection = transport.connect(server, deadline).await.unwrap();
    let (mut send, _receive) = connection.open_bi().await.unwrap();
    send.write_all(&[0, 100, 1]).await.unwrap();

    let stopped = time::timeout(Duration::from_secs(2), send.stopped())
        .await
        .expect("the absolute stream deadline must stop a partial request")
        .unwrap();
    assert_eq!(stopped, Some(DOQ_REQUEST_CANCELLED));

    let response = transport
        .exchange(server, &query(17, QueryType::A), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(response.headers.id, 17);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn non_reading_stream_times_out_without_closing_connection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server_with_timeout(
        BackpressuredHandler(Arc::clone(&calls)),
        Duration::from_millis(100),
    )
    .await;
    let transport = DoqTransport::new(client_config());
    let deadline = time::Instant::now() + Duration::from_secs(2);
    let connection = transport.connect(server, deadline).await.unwrap();
    let (mut send, _receive) = connection.open_bi().await.unwrap();
    let request = prepare_query(&query(0, QueryType::AXFR)).unwrap();
    write_frame(&mut send, &request.into_wire().unwrap())
        .await
        .unwrap();
    send.finish().unwrap();

    time::sleep(Duration::from_millis(250)).await;
    assert!(connection.close_reason().is_none());
    let response = transport
        .exchange(server, &query(18, QueryType::A), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(response.headers.id, 18);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
}

struct InlineTransferHandler;

impl DnsRequestHandler for InlineTransferHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let name = request.message().questions[0].qname.clone();
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            assert!(request.respond_stream(receiver));
            // The second send can complete only once the server drains the first
            // frame while this handler is still running.
            for _ in 0..2 {
                sender
                    .send(Message {
                        headers: Headers::default(),
                        questions: Vec::new(),
                        answers: vec![soa(name.clone())],
                        authorities: Vec::new(),
                        additionals: Vec::new(),
                    })
                    .await
                    .unwrap();
            }
        })
    }
}

#[tokio::test]
async fn drains_bounded_axfr_stream_before_handler_returns() {
    let (server, task) = one_connection_server(InlineTransferHandler).await;
    let records = DoqTransport::new(client_config())
        .transfer(server, &query(92, QueryType::AXFR), Duration::from_secs(2))
        .await
        .expect("inline AXFR producer must run concurrently with stream consumption");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].rdata, records[1].rdata);
    task.abort();
}

#[tokio::test]
async fn preserves_signed_questionless_update_responses() {
    for case in crate::tests::signed_responses::SignedResponse::cases(0) {
        let (address, task) = one_connection_server(case.handler()).await;
        let transport = DoqTransport::new(client_config());
        let response = transport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.abort();
    }
}

#[tokio::test]
async fn preserves_inverse_response_discovered_questions() {
    for case in crate::tests::signed_responses::SignedResponse::inverse_cases(0) {
        let (address, task) = one_connection_server(case.handler()).await;
        let transport = DoqTransport::new(client_config());
        let response = transport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.abort();
    }
}

mod padding;
mod protocol;
mod transfers;

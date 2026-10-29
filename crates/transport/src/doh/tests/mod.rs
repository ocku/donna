use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use dns::{
    ClassType, Headers, QClassType, QueryType, Question, RData, RecordType, ResourceRecord,
    TsigAlgorithm, TsigErrorCode, TsigKey,
};
use http::{Response, StatusCode};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{
    DnsRequestHandler,
    tests::fixtures::{certificate, private_key},
};

use super::cache::freshness_lifetime;

fn query(id: u16) -> Message {
    Message::builder()
        .headers(Headers {
            id,
            ..Headers::default()
        })
        .questions([Question {
            qname: dns::DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap()
}

fn client_config(method: DohMethod) -> DohClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(certificate()).unwrap();
    DohClientConfig::new(
        roots,
        "localhost".to_owned(),
        "localhost".to_owned(),
        "/dns-query".to_owned(),
        method,
    )
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
    request_timeout: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    H: DnsRequestHandler + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config =
        DohServerConfig::new(vec![certificate()], private_key(), "/dns-query".to_owned()).unwrap();
    let task = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(config.tls).accept(tcp).await.unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(H2_ALPN));
        let connection = doh_server_builder().handshake(tls).await.unwrap();
        let handler = Arc::new(handler);
        serve_connection(
            connection,
            peer,
            "/dns-query".to_owned(),
            handler,
            request_timeout,
            None,
        )
        .await;
    });
    (address, task)
}

async fn one_http_response_server(
    age: &'static str,
    dns_response: Message,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<Option<header::HeaderValue>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config =
        DohServerConfig::new(vec![certificate()], private_key(), "/dns-query".to_owned()).unwrap();
    let (headers_sender, headers_receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(config.tls).accept(tcp).await.unwrap();
        let mut connection = doh_server_builder().handshake(tls).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let _ = headers_sender.send(request.headers().get(header::CACHE_CONTROL).cloned());
        let (_, mut request_body) = request.into_parts();
        while let Some(chunk) = request_body.data().await {
            let chunk = chunk.unwrap();
            request_body
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
        }
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, DOH_MEDIA_TYPE)
            .header(header::AGE, age)
            .body(())
            .unwrap();
        let mut body = respond.send_response(response, false).unwrap();
        body.send_data(Bytes::from(dns_response.into_wire().unwrap()), true)
            .unwrap();
        drop(body);
        let _ = time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    (address, headers_receiver, task)
}

async fn observed_one_connection_server<H>(
    handler: H,
    request_task_metrics: Arc<RequestTaskMetrics>,
) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    H: DnsRequestHandler + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config =
        DohServerConfig::new(vec![certificate()], private_key(), "/dns-query".to_owned()).unwrap();
    let task = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(config.tls).accept(tcp).await.unwrap();
        let connection = doh_server_builder().handshake(tls).await.unwrap();
        serve_connection(
            connection,
            peer,
            "/dns-query".to_owned(),
            Arc::new(handler),
            HANDLER_TIMEOUT,
            Some(&request_task_metrics),
        )
        .await;
    });
    (address, task)
}

mod cache_authentication;
mod connection_flow;
mod protocol;

#[cfg(feature = "tcp")]
mod signed_responses;

mod edns_errors;

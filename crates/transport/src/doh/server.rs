use std::{future::poll_fn, io, net::SocketAddr, sync::Arc, time::Duration};

use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::Bytes;
use dns::{FromWire, IntoWire, Message};
use h2::server::SendResponse;
use http::{Method, Request, Response, StatusCode, header};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time,
};
use tokio_rustls::TlsAcceptor;
use tracing::instrument;

use crate::{
    DnsRequest, DnsRequestHandler, DnsResponse, MAX_TCP_MESSAGE_OCTETS, TransportProtocol,
    TransportServer, authenticated_response_headers_match, has_tsig, normalize_response_headers,
    request_questions_are_safe_to_echo, same_questions,
};

use super::{
    CONNECTION_IDLE_TIMEOUT, DOH_MEDIA_TYPE, DohServerConfig, H2_ALPN, HANDLER_TIMEOUT,
    HANDSHAKE_TIMEOUT, MAX_CONCURRENT_CONNECTIONS, MAX_CONCURRENT_REQUESTS,
    cache::freshness_lifetime,
};

pub(super) fn doh_server_builder() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder.max_concurrent_streams(MAX_CONCURRENT_REQUESTS as u32);
    builder.max_header_list_size(128 * 1024);
    builder
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct RequestTaskMetrics {
    pub(super) retained: std::sync::atomic::AtomicUsize,
    pub(super) high_water: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl RequestTaskMetrics {
    fn observe(&self, retained: usize) {
        use std::sync::atomic::Ordering;

        self.retained.store(retained, Ordering::SeqCst);
        self.high_water.fetch_max(retained, Ordering::SeqCst);
    }
}

/// Dedicated HTTP/2 DoH listener.
#[derive(Debug, Clone)]
pub struct DohTransportServer {
    config: DohServerConfig,
}

impl DohTransportServer {
    /// Creates a DoH listener from an authenticated server configuration.
    pub fn new(config: DohServerConfig) -> Self {
        Self { config }
    }
}

impl TransportServer for DohTransportServer {
    #[instrument(level = "debug", skip(self, handler), fields(address = %address))]
    fn serve<'future, H>(
        self,
        address: SocketAddr,
        handler: H,
    ) -> crate::BoxFuture<'future, Result<(), io::Error>>
    where
        H: DnsRequestHandler + 'static,
        Self: 'future,
    {
        Box::pin(async move {
            let listener = TcpListener::bind(address).await?;
            let acceptor = TlsAcceptor::from(self.config.tls);
            let handler = Arc::new(handler);
            let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
            loop {
                let permit = Arc::clone(&permits)
                    .acquire_owned()
                    .await
                    .map_err(|_| io::Error::other("DoH admission semaphore closed"))?;
                let (tcp, peer) = crate::listener_io::accept(&listener).await?;
                let acceptor = acceptor.clone();
                let handler = Arc::clone(&handler);
                let path = self.config.path.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let tls = match time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        Ok(Ok(tls)) => tls,
                        Ok(Err(error)) => {
                            tracing::debug!(%peer, ?error, "DoH TLS handshake failed");
                            return;
                        }
                        Err(_) => return,
                    };
                    let (_, connection) = tls.get_ref();
                    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
                        || connection.alpn_protocol() != Some(H2_ALPN)
                    {
                        return;
                    }
                    let connection =
                        match time::timeout(HANDSHAKE_TIMEOUT, doh_server_builder().handshake(tls))
                            .await
                        {
                            Ok(Ok(connection)) => connection,
                            Ok(Err(error)) => {
                                tracing::debug!(%peer, ?error, "DoH HTTP/2 handshake failed");
                                return;
                            }
                            Err(_) => {
                                tracing::debug!(%peer, "DoH HTTP/2 handshake timed out");
                                return;
                            }
                        };
                    serve_connection(
                        connection,
                        peer,
                        path,
                        handler,
                        HANDLER_TIMEOUT,
                        #[cfg(test)]
                        None,
                    )
                    .await;
                });
            }
        })
    }
}

pub(super) async fn serve_connection<H>(
    mut connection: h2::server::Connection<tokio_rustls::server::TlsStream<TcpStream>, Bytes>,
    peer: SocketAddr,
    path: String,
    handler: Arc<H>,
    request_timeout: Duration,
    #[cfg(test)] request_task_metrics: Option<&RequestTaskMetrics>,
) where
    H: DnsRequestHandler + 'static,
{
    let requests = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
    let mut request_tasks = JoinSet::new();
    'connection: loop {
        let request_permit = loop {
            match Arc::clone(&requests).try_acquire_owned() {
                Ok(permit) => break permit,
                Err(tokio::sync::TryAcquireError::Closed) => break 'connection,
                Err(tokio::sync::TryAcquireError::NoPermits) => {
                    // The h2 connection must keep being polled while every
                    // admitted request is waiting for body data or response
                    // I/O. poll_closed drives that I/O without dequeuing a new
                    // stream; the advertised HTTP/2 stream limit bounds the
                    // requests h2 can queue internally while saturated.
                    tokio::select! {
                        result = poll_fn(|context| connection.poll_closed(context)) => {
                            if let Err(error) = result {
                                tracing::debug!(%peer, ?error, "DoH stream failed");
                            }
                            break 'connection;
                        }
                        result = request_tasks.join_next() => {
                            if let Some(result) = result {
                                log_request_task_result(peer, result);
                                #[cfg(test)]
                                if let Some(metrics) = request_task_metrics {
                                    metrics.observe(request_tasks.len());
                                }
                            }
                        }
                    }
                }
            }
        };

        while let Some(result) = request_tasks.try_join_next() {
            log_request_task_result(peer, result);
        }
        #[cfg(test)]
        if let Some(metrics) = request_task_metrics {
            metrics.observe(request_tasks.len());
        }
        let accepted = time::timeout(CONNECTION_IDLE_TIMEOUT, async {
            loop {
                tokio::select! {
                    result = connection.accept() => return result,
                    result = request_tasks.join_next(), if !request_tasks.is_empty() => {
                        if let Some(result) = result {
                            log_request_task_result(peer, result);
                            #[cfg(test)]
                            if let Some(metrics) = request_task_metrics {
                                metrics.observe(request_tasks.len());
                            }
                        }
                    }
                }
            }
        })
        .await;
        let Some(result) = (match accepted {
            Ok(result) => result,
            Err(_) => {
                tracing::debug!(%peer, "closing idle DoH connection");
                break;
            }
        }) else {
            break;
        };
        let (request, respond) = match result {
            Ok(value) => value,
            Err(error) => {
                tracing::debug!(%peer, ?error, "DoH stream failed");
                break;
            }
        };
        let handler = Arc::clone(&handler);
        let path = path.clone();
        request_tasks.spawn(async move {
            let _permit = request_permit;
            serve_request_with_timeout(request, respond, peer, &path, handler, request_timeout)
                .await;
        });
        #[cfg(test)]
        if let Some(metrics) = request_task_metrics {
            metrics.observe(request_tasks.len());
        }
    }
    request_tasks.shutdown().await;
    #[cfg(test)]
    if let Some(metrics) = request_task_metrics {
        metrics.observe(0);
    }
}

fn log_request_task_result(peer: SocketAddr, result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        tracing::warn!(%peer, ?error, "DoH request task failed");
    }
}

async fn serve_request_with_timeout<H>(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer: SocketAddr,
    path: &str,
    handler: Arc<H>,
    request_timeout: Duration,
) where
    H: DnsRequestHandler + 'static,
{
    let wire = match time::timeout(request_timeout, decode_request(request, path)).await {
        Ok(Ok(wire)) => wire,
        Ok(Err(status)) => {
            send_empty_response(&mut respond, status);
            return;
        }
        Err(_) => {
            send_empty_response(&mut respond, StatusCode::REQUEST_TIMEOUT);
            return;
        }
    };
    let query = match Message::from_wire(&wire) {
        Ok(query) if !query.headers.qr => query,
        _ => {
            send_empty_response(&mut respond, StatusCode::BAD_REQUEST);
            return;
        }
    };
    let request_is_authenticated = has_tsig(&query);
    let request_headers = query.headers.clone();
    let request_questions = query.questions.clone();
    let request_message = query.clone();
    let (dns_request, response) =
        DnsRequest::channel_with_wire(query, wire, peer, TransportProtocol::Https);
    let response = match time::timeout(request_timeout, async {
        let ((), response) = tokio::join!(handler.handle(dns_request), response);
        response
    })
    .await
    {
        Ok(Ok(DnsResponse::Buffered(responses))) if responses.is_single() => {
            let mut response = responses.into_single().expect("length checked");
            if has_tsig(&response) {
                if !authenticated_response_headers_match(&request_headers, &response)
                    || (request_headers.opcode == dns::OpCode::Query
                        && !same_questions(&response.questions, &request_questions))
                {
                    send_empty_response(&mut respond, StatusCode::INTERNAL_SERVER_ERROR);
                    return;
                }
            } else {
                normalize_response_headers(&request_headers, &mut response);
                if request_headers.opcode == dns::OpCode::Query {
                    if request_questions_are_safe_to_echo(&request_questions) {
                        response.questions = request_questions;
                    } else {
                        response.questions.clear();
                    }
                }
                if prepare_response_padding(&request_message, &mut response).is_err() {
                    send_empty_response(&mut respond, StatusCode::INTERNAL_SERVER_ERROR);
                    return;
                }
            }
            let response_is_authenticated = has_tsig(&response);
            let freshness = (!request_is_authenticated && !response_is_authenticated)
                .then(|| freshness_lifetime(&response));
            match response.into_wire() {
                Ok(wire) => (wire, freshness),
                Err(_) => {
                    send_empty_response(&mut respond, StatusCode::INTERNAL_SERVER_ERROR);
                    return;
                }
            }
        }
        Ok(Ok(DnsResponse::Stream(responses))) => {
            // DoH carries one DNS message. Cancel a streaming producer rather
            // than retaining a receiver that this transport cannot consume.
            drop(responses);
            send_empty_response(&mut respond, StatusCode::INTERNAL_SERVER_ERROR);
            return;
        }
        _ => {
            send_empty_response(&mut respond, StatusCode::INTERNAL_SERVER_ERROR);
            return;
        }
    };
    let (wire, freshness) = response;
    let cache_control = freshness.map_or_else(
        || "no-store, no-cache".to_owned(),
        |freshness| format!("max-age={freshness}"),
    );
    let http_response = match Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, DOH_MEDIA_TYPE)
        .header(header::CACHE_CONTROL, cache_control)
        .body(())
    {
        Ok(response) => response,
        Err(_) => return,
    };
    if let Ok(mut body) = respond.send_response(http_response, false) {
        let _ = body.send_data(Bytes::from(wire), true);
    }
}

async fn decode_request(
    request: Request<h2::RecvStream>,
    path: &str,
) -> Result<Vec<u8>, StatusCode> {
    if request.uri().scheme_str() != Some("https") {
        return Err(StatusCode::BAD_REQUEST);
    }
    match *request.method() {
        Method::GET => {
            if request.uri().path() != path {
                return Err(StatusCode::NOT_FOUND);
            }
            let query = request.uri().query().ok_or(StatusCode::BAD_REQUEST)?;
            let encoded = query.strip_prefix("dns=").ok_or(StatusCode::BAD_REQUEST)?;
            if encoded.is_empty() || encoded.contains('&') || encoded.contains('=') {
                return Err(StatusCode::BAD_REQUEST);
            }
            if !request.body().is_end_stream() {
                return Err(StatusCode::BAD_REQUEST);
            }
            let wire =
                Base64UrlUnpadded::decode_vec(encoded).map_err(|_| StatusCode::BAD_REQUEST)?;
            if wire.len() > MAX_TCP_MESSAGE_OCTETS {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Ok(wire)
        }
        Method::POST => {
            if request.uri().path() != path || request.uri().query().is_some() {
                return Err(StatusCode::NOT_FOUND);
            }
            let content_type = request
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .ok_or(StatusCode::UNSUPPORTED_MEDIA_TYPE)?;
            if !content_type.eq_ignore_ascii_case(DOH_MEDIA_TYPE) {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            let (_, mut body) = request.into_parts();
            receive_server_body(&mut body).await
        }
        _ => Err(StatusCode::METHOD_NOT_ALLOWED),
    }
}

async fn receive_server_body(body: &mut h2::RecvStream) -> Result<Vec<u8>, StatusCode> {
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_TCP_MESSAGE_OCTETS {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn prepare_response_padding(request: &Message, response: &mut Message) -> Result<(), ()> {
    // The handler can correctly answer malformed EDNS with DNS FORMERR.
    // Ignore that request's padding preferences instead of replacing the reply
    // with an unrelated HTTP error. Response encoding still validates output.
    let Ok(request_edns) = request.edns() else {
        remove_padding(response);
        return Ok(());
    };
    if request_edns
        .as_ref()
        .is_some_and(|edns| edns.validate_options().is_err())
    {
        remove_padding(response);
        return Ok(());
    }
    let request_uses_padding = request_edns
        .as_ref()
        .is_some_and(|edns| edns.padding().is_some());
    if request_edns.is_some() && response.edns().map_err(|_| ())?.is_none() {
        response
            .additionals
            .push(dns::Edns::default().into_record());
    }
    if request_uses_padding {
        let request = crate::message::stream_padding_request(request);
        match response.pad_response_for_encrypted_transport(&request, MAX_TCP_MESSAGE_OCTETS) {
            Ok(_) => {}
            Err(dns::PaddingPolicyError::MessageTooLarge { .. }) => remove_padding(response),
            Err(_) => return Err(()),
        }
    } else {
        remove_padding(response);
    }
    Ok(())
}

fn remove_padding(message: &mut Message) {
    for record in &mut message.additionals {
        if let dns::RData::OPT(options) = &mut record.rdata {
            options.retain(|option| !option.is_padding());
        }
    }
}

fn send_empty_response(respond: &mut SendResponse<Bytes>, status: StatusCode) {
    if let Ok(response) = Response::builder().status(status).body(()) {
        let _ = respond.send_response(response, true);
    }
}

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use dns::{FromWire, Message};
use quinn::{Connection, Endpoint};
use tokio::{sync::Semaphore, time};
use tracing::instrument;

use crate::{
    DnsRequest, DnsRequestHandler, DnsResponse, MAX_TCP_MESSAGE_OCTETS, TransportProtocol,
    TransportServer, request_questions_are_safe_to_echo,
    tcp::{self, TransferSeriesValidator, write_frame},
};

use super::{
    DOQ_INTERNAL_ERROR, DOQ_PROTOCOL_ERROR, DOQ_REQUEST_CANCELLED, DoqServerConfig,
    HANDLER_TIMEOUT, MAX_AXFR_VALIDATION_RRSETS, MAX_CONCURRENT_CONNECTIONS, validate_message,
};

/// Dedicated UDP listener for DNS-over-QUIC connections.
#[derive(Debug, Clone)]
pub struct DoqTransportServer {
    config: DoqServerConfig,
}

impl DoqTransportServer {
    /// Creates a DoQ listener from an authenticated server configuration.
    pub fn new(config: DoqServerConfig) -> Self {
        Self { config }
    }
}

impl TransportServer for DoqTransportServer {
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
            if address.port() == 53 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DoQ must not use UDP port 53",
                ));
            }
            let socket = super::socket::ServerSocket::bind(address)?;
            let endpoint = Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(self.config.0),
                socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            let handler = Arc::new(handler);
            let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
            while let Some(incoming) = endpoint.accept().await {
                let permit = Arc::clone(&permits)
                    .acquire_owned()
                    .await
                    .map_err(|_| io::Error::other("DoQ admission semaphore closed"))?;
                if !incoming.remote_address_validated() {
                    match incoming.retry() {
                        Ok(()) => {
                            drop(permit);
                            continue;
                        }
                        Err(error) => {
                            let handler = Arc::clone(&handler);
                            tokio::spawn(serve_connection(error.into_incoming(), handler, permit));
                        }
                    }
                } else {
                    let handler = Arc::clone(&handler);
                    tokio::spawn(serve_connection(incoming, handler, permit));
                }
            }
            Ok(())
        })
    }
}

async fn serve_connection<H>(
    incoming: quinn::Incoming,
    handler: Arc<H>,
    permit: tokio::sync::OwnedSemaphorePermit,
) where
    H: DnsRequestHandler + 'static,
{
    serve_connection_with_stream_timeout(incoming, handler, permit, HANDLER_TIMEOUT).await;
}

pub(super) async fn serve_connection_with_stream_timeout<H>(
    incoming: quinn::Incoming,
    handler: Arc<H>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    stream_timeout: Duration,
) where
    H: DnsRequestHandler + 'static,
{
    let connection = match incoming.await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::debug!(?error, "DoQ handshake failed");
            return;
        }
    };
    loop {
        let (send, receive) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(_) => return,
        };
        let handler = Arc::clone(&handler);
        let connection = connection.clone();
        tokio::spawn(async move {
            serve_stream(send, receive, connection, handler, stream_timeout).await;
        });
    }
}

async fn serve_stream<H>(
    mut send: quinn::SendStream,
    mut receive: quinn::RecvStream,
    connection: Connection,
    handler: Arc<H>,
    stream_timeout: Duration,
) where
    H: DnsRequestHandler + 'static,
{
    let Some(deadline) = time::Instant::now().checked_add(stream_timeout) else {
        send.reset(DOQ_INTERNAL_ERROR).ok();
        receive.stop(DOQ_INTERNAL_ERROR).ok();
        return;
    };
    // Monitor cancellation throughout the transaction, including waits for a
    // streamed response producer. Dropping the work future also aborts its
    // HandlerTask and closes the producer's response channel.
    let stopped = send.stopped();
    let failure = tokio::select! {
        _ = stopped => StreamFailure::Cancelled,
        result = time::timeout_at(
            deadline,
            serve_stream_until_deadline(
                &mut send,
                &mut receive,
                connection.clone(),
                handler,
                deadline,
            ),
        ) => match result {
            Ok(Ok(())) => return,
            Ok(Err(failure)) => failure,
            Err(_) => StreamFailure::Timeout,
        },
    };
    let code = match failure {
        StreamFailure::Protocol => {
            connection.close(DOQ_PROTOCOL_ERROR, b"invalid DoQ message");
            return;
        }
        StreamFailure::Internal => DOQ_INTERNAL_ERROR,
        StreamFailure::Timeout | StreamFailure::Cancelled => DOQ_REQUEST_CANCELLED,
    };
    send.reset(code).ok();
    receive.stop(code).ok();
}

#[derive(Clone, Copy)]
enum StreamFailure {
    Protocol,
    Internal,
    Cancelled,
    Timeout,
}

struct HandlerTask(tokio::task::JoinHandle<()>);

impl Drop for HandlerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn serve_stream_until_deadline<H>(
    send: &mut quinn::SendStream,
    receive: &mut quinn::RecvStream,
    connection: Connection,
    handler: Arc<H>,
    deadline: time::Instant,
) -> Result<(), StreamFailure>
where
    H: DnsRequestHandler + 'static,
{
    let request_wire = receive
        .read_to_end(MAX_TCP_MESSAGE_OCTETS + 2)
        .await
        .map_err(|error| match error {
            quinn::ReadToEndError::TooLong => StreamFailure::Protocol,
            quinn::ReadToEndError::Read(_) => StreamFailure::Cancelled,
        })?;
    let wire = one_framed_message(&request_wire).map_err(|_| StreamFailure::Protocol)?;
    let query = Message::from_wire(wire).map_err(|_| StreamFailure::Protocol)?;
    if query.headers.qr || query.headers.id != 0 || validate_message(&query).is_err() {
        return Err(StreamFailure::Protocol);
    }
    let peer = connection.remote_address();
    let request_headers = query.headers.clone();
    let request_questions = query.questions.clone();
    let is_axfr =
        matches!(query.questions.as_slice(), [question] if question.qtype == dns::QueryType::AXFR);
    let is_ixfr =
        matches!(query.questions.as_slice(), [question] if question.qtype == dns::QueryType::IXFR);
    let request_message = query.clone();
    let (request, response) =
        DnsRequest::channel_with_wire(query, wire.to_vec(), peer, TransportProtocol::Quic);
    let mut handler_task = HandlerTask(tokio::spawn(async move { handler.handle(request).await }));
    let response = tokio::select! {
        stopped = send.stopped() => {
            if matches!(stopped, Ok(Some(_))) {
                return Ok(());
            }
            return Err(StreamFailure::Cancelled);
        }
        response = time::timeout_at(deadline, response) => match response {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return Err(StreamFailure::Internal),
            Err(_) => return Err(StreamFailure::Timeout),
        }
    };

    match response {
        DnsResponse::Buffered(responses) => {
            let responses = responses.into_vec();
            if responses
                .iter()
                .any(|message| validate_message(message).is_err())
            {
                return Err(StreamFailure::Internal);
            }
            if wait_for_handler(send, &mut handler_task, deadline).await? {
                return Ok(());
            }
            let frames = if is_axfr {
                tcp::prepare_axfr_responses(
                    responses,
                    &request_headers,
                    &request_questions,
                    MAX_AXFR_VALIDATION_RRSETS,
                    Some((&request_message, TransportProtocol::Quic)),
                )
            } else if is_ixfr {
                tcp::prepare_ixfr_response(
                    responses,
                    &request_headers,
                    request_questions,
                    &request_message,
                    Some(TransportProtocol::Quic),
                )
            } else {
                tcp::prepare_standard_response_for(
                    responses,
                    &request_headers,
                    request_questions,
                    Some((&request_message, TransportProtocol::Quic)),
                )
            }
            .ok_or(StreamFailure::Internal)?;
            for frame in frames {
                write_frame(send, &frame)
                    .await
                    .map_err(|_| StreamFailure::Cancelled)?;
            }
        }
        DnsResponse::Stream(mut responses) => {
            // Inline producers can await bounded channel capacity, so drain
            // their frames before waiting for the handler to finish.
            if !is_axfr && !is_ixfr {
                return Err(StreamFailure::Internal);
            }
            let question = request_questions
                .first()
                .cloned()
                .ok_or(StreamFailure::Internal)?;
            let mut validator = TransferSeriesValidator::new(
                question,
                request_questions_are_safe_to_echo(&request_questions),
                MAX_AXFR_VALIDATION_RRSETS,
                &request_message,
            );
            while let Some(response) = time::timeout_at(deadline, responses.recv())
                .await
                .map_err(|_| StreamFailure::Timeout)?
            {
                validate_message(&response).map_err(|_| StreamFailure::Internal)?;
                let frame = validator
                    .prepare(
                        response,
                        &request_headers,
                        &request_questions,
                        Some((&request_message, TransportProtocol::Quic)),
                    )
                    .ok_or(StreamFailure::Internal)?;
                write_frame(send, &frame)
                    .await
                    .map_err(|_| StreamFailure::Cancelled)?;
            }
            if !validator.finish() {
                return Err(StreamFailure::Internal);
            }
            if wait_for_handler(send, &mut handler_task, deadline).await? {
                return Ok(());
            }
        }
    }
    send.finish().map_err(|_| StreamFailure::Cancelled)?;
    Ok(())
}

async fn wait_for_handler(
    send: &mut quinn::SendStream,
    handler_task: &mut HandlerTask,
    deadline: time::Instant,
) -> Result<bool, StreamFailure> {
    tokio::select! {
        stopped = send.stopped() => match stopped {
            Ok(Some(_)) => Ok(true),
            _ => Err(StreamFailure::Cancelled),
        },
        result = time::timeout_at(deadline, &mut handler_task.0) => match result {
            Ok(Ok(())) => Ok(false),
            Ok(Err(_)) => Err(StreamFailure::Internal),
            Err(_) => Err(StreamFailure::Timeout),
        }
    }
}

pub(super) fn one_framed_message(packet: &[u8]) -> Result<&[u8], ()> {
    let length = usize::from(u16::from_be_bytes([
        *packet.first().ok_or(())?,
        *packet.get(1).ok_or(())?,
    ]));
    if length == 0 || packet.len() != length + 2 {
        return Err(());
    }
    Ok(&packet[2..])
}

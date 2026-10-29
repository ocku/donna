//! DNS over QUIC (DoQ) with one DNS transaction per bidirectional stream.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use dns::{FromWire, IntoWire, Message};
use quinn::{Connection, Endpoint, VarInt};
use tokio::{
    sync::{Mutex as AsyncMutex, Semaphore},
    time,
};
use tracing::instrument;

use crate::{
    Transport, TransportError, TransportProtocol, checked_deadline, has_tsig,
    tcp::{self, axfr::receive_transfer_checked, read_frame, write_frame},
};

mod config;
mod server;
mod socket;
mod validation;
use validation::{
    peer_result, prepare_query, reject_port_53, require_fin, validate_message, with_peer_stop,
};

pub use config::{DoqClientConfig, DoqConfigError, DoqServerConfig};
pub use server::DoqTransportServer;
#[cfg(test)]
use server::{one_framed_message, serve_connection_with_stream_timeout};

/// The IANA-assigned UDP port for DNS over QUIC.
pub const DOQ_PORT: u16 = 853;
/// The ALPN protocol identifier for DNS over QUIC.
pub const DOQ_ALPN: &[u8] = b"doq";

const MAX_POOLED_CONNECTIONS: usize = 64;
const MAX_CONCURRENT_CONNECTS: usize = 64;
const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const MAX_AXFR_VALIDATION_RRSETS: usize = 1_000_000;
const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

const DOQ_NO_ERROR: VarInt = VarInt::from_u32(0);
const DOQ_INTERNAL_ERROR: VarInt = VarInt::from_u32(1);
const DOQ_PROTOCOL_ERROR: VarInt = VarInt::from_u32(2);
const DOQ_REQUEST_CANCELLED: VarInt = VarInt::from_u32(3);

/// Own both stream halves so dropping an exchange future cancels the request
/// with DoQ's registered code. Quinn's default drop uses application code zero.
struct TransactionStream {
    send: quinn::SendStream,
    receive: quinn::RecvStream,
    completed: bool,
}

impl TransactionStream {
    fn new((send, receive): (quinn::SendStream, quinn::RecvStream)) -> Self {
        Self {
            send,
            receive,
            completed: false,
        }
    }
}

impl Drop for TransactionStream {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.receive.stop(DOQ_REQUEST_CANCELLED).ok();
        self.send.reset(DOQ_REQUEST_CANCELLED).ok();
    }
}

/// Reusable DNS-over-QUIC client.
#[derive(Clone)]
pub struct DoqTransport {
    config: DoqClientConfig,
    endpoints: Arc<Mutex<HashMap<bool, Endpoint>>>,
    connections: Arc<Mutex<HashMap<SocketAddr, Connection>>>,
    connect_locks: Arc<Mutex<HashMap<SocketAddr, Weak<AsyncMutex<()>>>>>,
    connect_permits: Arc<Semaphore>,
}

impl std::fmt::Debug for DoqTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DoqTransport")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DoqTransport {
    /// Creates a reusable DoQ client.
    pub fn new(config: DoqClientConfig) -> Self {
        Self {
            config,
            endpoints: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            connect_locks: Arc::new(Mutex::new(HashMap::new())),
            connect_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTS)),
        }
    }

    fn connect_lock(&self, server: SocketAddr) -> Arc<AsyncMutex<()>> {
        let mut locks = self
            .connect_locks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&server).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(server, Arc::downgrade(&lock));
        lock
    }

    fn endpoint(&self, ipv6: bool) -> Result<Endpoint, TransportError> {
        let mut endpoints = self
            .endpoints
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(endpoint) = endpoints.get(&ipv6) {
            return Ok(endpoint.clone());
        }
        let bind = if ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let mut endpoint = Endpoint::client(bind)?;
        endpoint.set_default_client_config(self.config.quic.clone());
        endpoints.insert(ipv6, endpoint.clone());
        Ok(endpoint)
    }

    async fn connect(
        &self,
        server: SocketAddr,
        deadline: time::Instant,
    ) -> Result<Connection, TransportError> {
        if let Some(connection) = self
            .connections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&server)
            .filter(|connection| connection.close_reason().is_none())
            .cloned()
        {
            return Ok(connection);
        }
        let connect_lock = self.connect_lock(server);
        let _singleflight = time::timeout_at(deadline, connect_lock.lock())
            .await
            .map_err(|_| TransportError::Timeout)?;
        if let Some(connection) = self
            .connections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&server)
            .filter(|connection| connection.close_reason().is_none())
            .cloned()
        {
            return Ok(connection);
        }
        let _permit = time::timeout_at(deadline, Arc::clone(&self.connect_permits).acquire_owned())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Io(io::Error::other("DoQ connect semaphore closed")))?;
        if let Some(connection) = self
            .connections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&server)
            .filter(|connection| connection.close_reason().is_none())
            .cloned()
        {
            return Ok(connection);
        }
        let endpoint = self.endpoint(server.is_ipv6())?;
        let connecting = endpoint
            .connect(server, &self.config.authentication_name)
            .map_err(quic_io_error)?;
        let connection = time::timeout_at(deadline, connecting)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(quic_io_error)?;
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        connections.retain(|_, connection| connection.close_reason().is_none());
        if let Some(existing) = connections
            .get(&server)
            .filter(|connection| connection.close_reason().is_none())
        {
            connection.close(DOQ_NO_ERROR, b"duplicate connection");
            return Ok(existing.clone());
        }
        if connections.len() >= MAX_POOLED_CONNECTIONS
            && let Some(victim) = connections.keys().next().copied()
        {
            // Dropping the pool's handle is safe for concurrent users, whose
            // clones keep the QUIC connection alive. Do not call `close`: that
            // would abort their in-flight streams.
            connections.remove(&victim);
        }
        connections.insert(server, connection.clone());
        Ok(connection)
    }

    fn evict(&self, server: SocketAddr, failed: &Connection) {
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if connections
            .get(&server)
            .is_some_and(|active| active.stable_id() == failed.stable_id())
        {
            connections.remove(&server);
        }
    }

    async fn exchange_once(
        &self,
        connection: &Connection,
        query: &Message,
        deadline: time::Instant,
    ) -> Result<Message, TransportError> {
        let request = query.into_wire().map_err(TransportError::encode)?;
        let mut stream = TransactionStream::new(
            time::timeout_at(deadline, connection.open_bi())
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(quic_io_error)?,
        );
        let stopped = stream.send.stopped();
        with_peer_stop(connection, stopped, async {
            time::timeout_at(deadline, write_frame(&mut stream.send, &request))
                .await
                .map_err(|_| TransportError::Timeout)??;
            stream.send.finish().map_err(quic_io_error)?;
            let packet = match time::timeout_at(deadline, read_frame(&mut stream.receive)).await {
                Ok(result) => peer_result(connection, result.map_err(TransportError::from))?,
                Err(_) => {
                    return Err(TransportError::Timeout);
                }
            };
            require_fin(connection, &mut stream.receive, deadline).await?;
            let mut response = peer_result(
                connection,
                Message::from_wire(&packet).map_err(TransportError::decode),
            )?;
            if let Err(error) = validate_message(&response) {
                connection.close(DOQ_PROTOCOL_ERROR, b"forbidden EDNS option");
                return Err(error);
            }
            if !tcp::matches_tcp_query(&response, query) {
                connection.close(DOQ_PROTOCOL_ERROR, b"response does not match query");
                return Err(TransportError::InvalidQuicProtocol(
                    "DNS response does not match the stream query",
                ));
            }
            if response.questions.is_empty() && !crate::has_tsig(&response) {
                response.questions.clone_from(&query.questions);
            }
            stream.completed = true;
            Ok(response)
        })
        .await
    }

    /// Transfers a zone on one QUIC stream with finite default limits.
    pub async fn transfer(
        &self,
        server: SocketAddr,
        query: &Message,
        timeout: Duration,
    ) -> Result<Vec<dns::ResourceRecord>, TransportError> {
        self.transfer_with_limits(server, query, timeout, crate::AxfrLimits::default())
            .await
    }

    /// Transfers a zone on one QUIC stream with explicit byte and record limits.
    pub async fn transfer_with_limits(
        &self,
        server: SocketAddr,
        query: &Message,
        timeout: Duration,
        limits: crate::AxfrLimits,
    ) -> Result<Vec<dns::ResourceRecord>, TransportError> {
        reject_port_53(server)?;
        let query = prepare_query(query)?;
        let request = tcp::axfr::prepare_transfer_request_for(&query, true)?;
        let deadline = checked_deadline(timeout)?;
        let connection = self.connect(server, deadline).await?;
        let mut stream = TransactionStream::new(
            time::timeout_at(deadline, connection.open_bi())
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(quic_io_error)?,
        );
        let stopped = stream.send.stopped();
        with_peer_stop(&connection, stopped, async {
            time::timeout_at(deadline, write_frame(&mut stream.send, &request))
                .await
                .map_err(|_| TransportError::Timeout)??;
            stream.send.finish().map_err(quic_io_error)?;
            let records = match receive_transfer_checked(
                &mut stream.receive,
                &query,
                deadline,
                limits,
                |response| {
                    if let Err(error) = validate_message(response) {
                        connection.close(DOQ_PROTOCOL_ERROR, b"forbidden EDNS option");
                        return Err(error);
                    }
                    Ok(())
                },
            )
            .await
            {
                Err(TransportError::Timeout) => {
                    return Err(TransportError::Timeout);
                }
                result => peer_result(&connection, result)?,
            };
            require_fin(&connection, &mut stream.receive, deadline).await?;
            stream.completed = true;
            Ok(records)
        })
        .await
    }
}

impl Transport for DoqTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Quic)
    }

    #[instrument(
        level = "debug",
        skip(self, query),
        fields(server = %server, transaction_id = query.headers.id, timeout = ?timeout)
    )]
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> crate::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            reject_port_53(server)?;
            let original_id = query.headers.id;
            let query = prepare_query(query)?;
            let deadline = checked_deadline(timeout)?;
            for retry in 0..=1 {
                let connection = self.connect(server, deadline).await?;
                let result = self.exchange_once(&connection, &query, deadline).await;
                if result.is_err() && connection.close_reason().is_some() {
                    self.evict(server, &connection);
                }
                if retry == 0 && matches!(result, Err(TransportError::Io(_))) {
                    self.evict(server, &connection);
                    continue;
                }
                return result.map(|mut response| {
                    response.headers.id = original_id;
                    response
                });
            }
            unreachable!("the bounded retry loop always returns")
        })
    }
}

fn quic_io_error(error: impl std::error::Error + Send + Sync + 'static) -> TransportError {
    TransportError::Io(io::Error::other(error))
}

#[cfg(test)]
mod tests;

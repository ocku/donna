use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use dns::{FromWire, IntoWire, Message};
use tokio::{
    net::TcpStream,
    sync::{Mutex as AsyncMutex, Semaphore},
    time,
};
use tokio_rustls::{TlsConnector, client::TlsStream as ClientTlsStream};
use tracing::instrument;

use crate::{
    MAX_TCP_MESSAGE_OCTETS, Transport, TransportError, TransportProtocol, checked_deadline,
    tcp::{self, read_frame, write_frame},
};

mod config;

pub use config::{TlsClientConfig, TlsClientConfigError};

const MAX_POOLED_TLS_SESSIONS: usize = 64;
const MAX_CONCURRENT_TLS_CONNECTS: usize = 64;

type PooledSession = Arc<AsyncMutex<ClientTlsStream<TcpStream>>>;
type SessionKey = (SocketAddr, SessionPurpose);
type SessionPool = Arc<Mutex<HashMap<SessionKey, PooledSession>>>;
type ConnectLocks = Arc<Mutex<HashMap<SessionKey, Weak<AsyncMutex<()>>>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SessionPurpose {
    Query,
    Transfer,
}

/// Exchanges ordinary DNS messages and AXFR series over authenticated TLS.
///
/// Ordinary exchanges reuse one authenticated session per server. Access to a
/// session is serialized, preserving safe response correlation without hiding
/// additional DNS transmissions from the resolver's work accounting.
#[derive(Clone)]
pub struct TlsTransport {
    config: TlsClientConfig,
    sessions: SessionPool,
    connect_locks: ConnectLocks,
    connect_permits: Arc<Semaphore>,
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsTransport")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl TlsTransport {
    /// Creates a reusable DNS-over-TLS client.
    pub fn new(config: TlsClientConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            connect_locks: Arc::new(Mutex::new(HashMap::new())),
            connect_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_TLS_CONNECTS)),
        }
    }

    fn connect_lock(&self, key: SessionKey) -> Arc<AsyncMutex<()>> {
        let mut locks = self
            .connect_locks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    async fn connect(
        &self,
        server: SocketAddr,
        purpose: SessionPurpose,
        deadline: time::Instant,
    ) -> Result<PooledSession, TransportError> {
        let key = (server, purpose);
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&key)
            .cloned()
        {
            return Ok(session);
        }

        let connect_lock = self.connect_lock(key);
        let _singleflight = time::timeout_at(deadline, connect_lock.lock())
            .await
            .map_err(|_| TransportError::Timeout)?;
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&key)
            .cloned()
        {
            return Ok(session);
        }

        // Bound simultaneous socket and handshake state even when many callers
        // miss the pool at once. The same end-to-end exchange deadline covers
        // waiting for admission as well as connection establishment.
        let _permit = time::timeout_at(deadline, Arc::clone(&self.connect_permits).acquire_owned())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Io(io::Error::other("TLS connect semaphore closed")))?;
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&key)
            .cloned()
        {
            return Ok(session);
        }

        let tcp = time::timeout_at(deadline, TcpStream::connect(server))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let connector = TlsConnector::from(Arc::clone(&self.config.config));
        let tls = time::timeout_at(
            deadline,
            connector.connect(self.config.authentication_name.clone(), tcp),
        )
        .await
        .map_err(|_| TransportError::Timeout)??;
        validate_client_session(&tls, purpose == SessionPurpose::Transfer)?;
        let candidate = Arc::new(AsyncMutex::new(tls));
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(session) = sessions.get(&key) {
            return Ok(Arc::clone(session));
        }
        if sessions.len() >= MAX_POOLED_TLS_SESSIONS {
            // Prefer an idle session, but removing an active Arc from the map
            // is also safe: its current user retains ownership and completes.
            let victim = sessions
                .iter()
                .find(|(_, session)| Arc::strong_count(session) == 1)
                .or_else(|| sessions.iter().next())
                .map(|(key, _)| *key);
            if let Some(victim) = victim {
                sessions.remove(&victim);
            }
        }
        sessions.insert(key, Arc::clone(&candidate));
        Ok(candidate)
    }

    fn session_is_current(&self, key: SessionKey, session: &PooledSession) -> bool {
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, session))
    }

    /// Transfers a zone over a reusable authenticated TLS 1.3 connection.
    pub async fn transfer(
        &self,
        server: SocketAddr,
        query: &Message,
        timeout: Duration,
    ) -> Result<Vec<dns::ResourceRecord>, TransportError> {
        self.transfer_with_limits(server, query, timeout, crate::AxfrLimits::default())
            .await
    }

    /// Transfers a zone over TLS with explicit cumulative byte and record limits.
    pub async fn transfer_with_limits(
        &self,
        server: SocketAddr,
        query: &Message,
        timeout: Duration,
        limits: crate::AxfrLimits,
    ) -> Result<Vec<dns::ResourceRecord>, TransportError> {
        let query = padded_query(query)?;
        let request = tcp::axfr::prepare_transfer_request_for(&query, true)?;
        let deadline = checked_deadline(timeout)?;
        // No records are exposed until the complete series has passed
        // validation, so an interrupted transfer can safely restart once on a
        // fresh authenticated connection under the original caller deadline.
        for retry in 0..=1 {
            let result = loop {
                let purpose = SessionPurpose::Transfer;
                let key = (server, purpose);
                let session = self.connect(server, purpose, deadline).await?;
                let mut stream = time::timeout_at(deadline, session.lock())
                    .await
                    .map_err(|_| TransportError::Timeout)?;
                // A waiter may have cloned this session before an interrupted
                // user evicted it. Never start another request on that stale
                // stream after acquiring its per-session lock.
                if !self.session_is_current(key, &session) {
                    drop(stream);
                    continue;
                }
                let mut use_guard =
                    SessionUseGuard::new(Arc::clone(&self.sessions), key, Arc::clone(&session));
                let result = async {
                    time::timeout_at(deadline, write_frame(&mut *stream, &request))
                        .await
                        .map_err(|_| TransportError::Timeout)??;
                    tcp::axfr::receive_transfer(&mut *stream, &query, deadline, limits).await
                }
                .await;
                if result.is_ok() {
                    use_guard.complete();
                }
                break result;
            };
            if retry == 0 && matches!(result, Err(TransportError::Io(_))) {
                continue;
            }
            return result;
        }
        unreachable!("the bounded retry loop always returns")
    }
}

impl Transport for TlsTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Tls)
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
            let query = padded_query(query)?;
            let request = query.into_wire().map_err(TransportError::encode)?;
            let deadline = checked_deadline(timeout)?;
            // A peer may close an idle persistent session at any time. Retry an I/O
            // failure once on a freshly authenticated connection, under the same
            // caller deadline; semantic, decoding, and timeout failures remain
            // terminal for this exchange.
            for retry in 0..=1 {
                let result = loop {
                    let purpose = SessionPurpose::Query;
                    let key = (server, purpose);
                    let session = self.connect(server, purpose, deadline).await?;
                    let mut stream = time::timeout_at(deadline, session.lock())
                        .await
                        .map_err(|_| TransportError::Timeout)?;
                    if !self.session_is_current(key, &session) {
                        drop(stream);
                        continue;
                    }
                    let mut use_guard =
                        SessionUseGuard::new(Arc::clone(&self.sessions), key, Arc::clone(&session));
                    let result = async {
                        time::timeout_at(deadline, write_frame(&mut *stream, &request))
                            .await
                            .map_err(|_| TransportError::Timeout)??;
                        loop {
                            let packet = time::timeout_at(deadline, read_frame(&mut *stream))
                                .await
                                .map_err(|_| TransportError::Timeout)??;
                            let mut response =
                                Message::from_wire(&packet).map_err(TransportError::decode)?;
                            if tcp::matches_tcp_query(&response, &query) {
                                if response.questions.is_empty() && !crate::has_tsig(&response) {
                                    response.questions.clone_from(&query.questions);
                                }
                                return Ok(response);
                            }
                        }
                    }
                    .await;
                    if result.is_ok() {
                        use_guard.complete();
                    }
                    break result;
                };
                if retry == 0 && matches!(result, Err(TransportError::Io(_))) {
                    continue;
                }
                return result;
            }
            unreachable!("the bounded retry loop always returns")
        })
    }
}

/// Evicts the exact pool generation if a request future is dropped before it
/// has consumed its complete response. This makes cancellation equivalent to
/// an I/O failure without disturbing a replacement session for the same key.
struct SessionUseGuard {
    sessions: SessionPool,
    key: SessionKey,
    session: PooledSession,
    completed: bool,
}

impl SessionUseGuard {
    fn new(sessions: SessionPool, key: SessionKey, session: PooledSession) -> Self {
        Self {
            sessions,
            key,
            session,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for SessionUseGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if sessions
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.session))
        {
            sessions.remove(&self.key);
        }
    }
}

fn padded_query(query: &Message) -> Result<Message, TransportError> {
    let mut query = query.clone();
    if !crate::has_tsig(&query)
        && query
            .edns()
            .map_err(|_| {
                TransportError::InvalidTlsProtocol("query contains malformed EDNS metadata")
            })?
            .is_some()
    {
        query
            .pad_query_for_encrypted_transport(MAX_TCP_MESSAGE_OCTETS)
            .map_err(TransportError::Padding)?;
    }
    Ok(query)
}

fn validate_client_session(
    stream: &ClientTlsStream<TcpStream>,
    require_dot_alpn: bool,
) -> Result<(), TransportError> {
    let (_, connection) = stream.get_ref();
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(TransportError::InvalidTlsProtocol(
            "TLS 1.3 was not negotiated",
        ));
    }
    super::validate_dot_alpn(connection.alpn_protocol(), require_dot_alpn)
}

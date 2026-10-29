//! DNS over HTTPS (DoH) using HTTP/2 over authenticated TLS.
//!
//! The endpoint path is explicit configuration. Clients never follow pushed
//! or advertised alternatives, and servers accept both RFC 8484 GET and POST
//! requests at the configured path.

mod cache;
mod client_request;
mod server;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use bytes::Bytes;
use dns::{FromWire, IntoWire, Message};
use h2::client::SendRequest;
use http::{Method, Request, header};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName},
};
use tokio::{
    net::TcpStream,
    sync::{Mutex as AsyncMutex, Semaphore},
    time,
};
use tokio_rustls::TlsConnector;
use tracing::instrument;

use crate::{Transport, TransportError, TransportProtocol, checked_deadline, has_tsig};

use cache::{apply_age, parse_age};
use client_request::{prepared_query, receive_body, request_uri};
pub use server::DohTransportServer;
#[cfg(test)]
use server::{RequestTaskMetrics, doh_server_builder, serve_connection};

/// The conventional HTTPS port used by DoH.
pub const DOH_PORT: u16 = 443;
/// The mandatory RFC 8484 DNS wire-format media type.
pub const DOH_MEDIA_TYPE: &str = "application/dns-message";
const H2_ALPN: &[u8] = b"h2";
const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const MAX_CONCURRENT_REQUESTS: usize = 64;
const MAX_POOLED_SESSIONS: usize = 64;
const MAX_CONCURRENT_CONNECTS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

type PooledSession = Arc<SendRequest<Bytes>>;

/// Selects the RFC 8484 request mapping used by a DoH client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMethod {
    /// Put unencoded DNS wire bytes in the POST request body.
    Post,
    /// Put unpadded base64url DNS wire bytes in the `dns` query parameter,
    /// using POST at the same endpoint if the encoded URI exceeds the HTTP
    /// library's limit.
    Get,
}

/// Reports invalid DoH endpoint or TLS configuration.
#[derive(Debug)]
pub enum DohConfigError {
    /// The TLS authentication name is not a valid DNS name.
    InvalidAuthenticationName(InvalidDnsNameError),
    /// The HTTP authority or endpoint path is invalid.
    InvalidEndpoint(&'static str),
    /// Rustls rejected the certificate or private key.
    Tls(rustls::Error),
}

impl std::fmt::Display for DohConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAuthenticationName(error) => error.fmt(formatter),
            Self::InvalidEndpoint(reason) => write!(formatter, "invalid DoH endpoint: {reason}"),
            Self::Tls(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DohConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAuthenticationName(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::InvalidEndpoint(_) => None,
        }
    }
}

/// Authenticated HTTP/2 client configuration for one configured DoH URI.
#[derive(Clone)]
pub struct DohClientConfig {
    tls: Arc<ClientConfig>,
    authentication_name: ServerName<'static>,
    authority: String,
    path: String,
    method: DohMethod,
}

impl std::fmt::Debug for DohClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DohClientConfig")
            .field("authentication_name", &self.authentication_name)
            .field("authority", &self.authority)
            .field("path", &self.path)
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl DohClientConfig {
    /// Builds a TLS 1.3 HTTP/2 client for the configured HTTPS authority and path.
    ///
    /// `authority` is the URI authority sent in HTTP (for example,
    /// `dns.example:443`). `authentication_name` is independently verified by
    /// TLS and must not be inferred from the socket address passed to exchange.
    pub fn new(
        root_certificates: RootCertStore,
        authentication_name: String,
        authority: String,
        path: String,
        method: DohMethod,
    ) -> Result<Self, DohConfigError> {
        let authentication_name = ServerName::try_from(authentication_name)
            .map_err(DohConfigError::InvalidAuthenticationName)?;
        validate_authority(&authority)?;
        validate_path(&path)?;
        let mut tls = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_certificates)
            .with_no_client_auth();
        tls.alpn_protocols = vec![H2_ALPN.to_vec()];
        Ok(Self {
            tls: Arc::new(tls),
            authentication_name,
            authority,
            path,
            method,
        })
    }
}

/// TLS configuration and endpoint path for a DoH server.
#[derive(Clone)]
pub struct DohServerConfig {
    tls: Arc<ServerConfig>,
    path: String,
}

impl std::fmt::Debug for DohServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DohServerConfig")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl DohServerConfig {
    /// Builds a TLS 1.3 HTTP/2 server for `path`.
    pub fn new(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        path: String,
    ) -> Result<Self, DohConfigError> {
        validate_path(&path)?;
        let mut tls = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .map_err(DohConfigError::Tls)?;
        tls.alpn_protocols = vec![H2_ALPN.to_vec()];
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        tls.ticketer = rustls::crypto::ring::Ticketer::new().map_err(DohConfigError::Tls)?;
        Ok(Self {
            tls: Arc::new(tls),
            path,
        })
    }
}

fn validate_authority(authority: &str) -> Result<(), DohConfigError> {
    let parsed = authority
        .parse::<http::uri::Authority>()
        .map_err(|_| DohConfigError::InvalidEndpoint("authority is not valid"))?;
    if parsed.as_str() != authority || authority.is_empty() {
        return Err(DohConfigError::InvalidEndpoint(
            "authority is not canonical",
        ));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), DohConfigError> {
    let parsed = path
        .parse::<http::uri::PathAndQuery>()
        .map_err(|_| DohConfigError::InvalidEndpoint("path is not a valid URI path"))?;
    if !path.starts_with('/') || parsed.query().is_some() || parsed.path() != path {
        return Err(DohConfigError::InvalidEndpoint(
            "path must be absolute and contain no query",
        ));
    }
    Ok(())
}

/// Reusable DNS-over-HTTPS client.
#[derive(Clone)]
pub struct DohTransport {
    config: DohClientConfig,
    sessions: Arc<Mutex<HashMap<SocketAddr, PooledSession>>>,
    connect_locks: Arc<Mutex<HashMap<SocketAddr, Weak<AsyncMutex<()>>>>>,
    connect_permits: Arc<Semaphore>,
}

impl std::fmt::Debug for DohTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DohTransport")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DohTransport {
    /// Creates a reusable HTTP/2 DoH client.
    pub fn new(config: DohClientConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
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

    async fn connect(
        &self,
        server: SocketAddr,
        deadline: time::Instant,
    ) -> Result<PooledSession, TransportError> {
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&server)
            .cloned()
        {
            return Ok(session);
        }
        let connect_lock = self.connect_lock(server);
        let _singleflight = time::timeout_at(deadline, connect_lock.lock())
            .await
            .map_err(|_| TransportError::Timeout)?;
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&server)
            .cloned()
        {
            return Ok(session);
        }
        let _permit = time::timeout_at(deadline, Arc::clone(&self.connect_permits).acquire_owned())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Io(io::Error::other("DoH connect semaphore closed")))?;
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&server)
            .cloned()
        {
            return Ok(session);
        }

        let tcp = time::timeout_at(deadline, TcpStream::connect(server))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let tls = time::timeout_at(
            deadline,
            TlsConnector::from(Arc::clone(&self.config.tls))
                .connect(self.config.authentication_name.clone(), tcp),
        )
        .await
        .map_err(|_| TransportError::Timeout)??;
        let (_, connection) = tls.get_ref();
        if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || connection.alpn_protocol() != Some(H2_ALPN)
        {
            return Err(TransportError::InvalidHttpProtocol(
                "TLS 1.3 with h2 ALPN was not negotiated",
            ));
        }
        let (sender, connection) = time::timeout_at(deadline, h2::client::handshake(tls))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(http_io_error)?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(?error, "DoH HTTP/2 connection closed");
            }
        });
        let candidate = Arc::new(sender);
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(session) = sessions.get(&server) {
            return Ok(Arc::clone(session));
        }
        if sessions.len() >= MAX_POOLED_SESSIONS {
            let victim = sessions
                .iter()
                .find(|(_, session)| Arc::strong_count(session) == 1)
                .or_else(|| sessions.iter().next())
                .map(|(server, _)| *server);
            if let Some(victim) = victim {
                sessions.remove(&victim);
            }
        }
        sessions.insert(server, Arc::clone(&candidate));
        Ok(candidate)
    }

    fn evict(&self, server: SocketAddr, failed: &PooledSession) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if sessions
            .get(&server)
            .is_some_and(|active| Arc::ptr_eq(active, failed))
        {
            sessions.remove(&server);
        }
    }

    async fn exchange_once(
        &self,
        session: &PooledSession,
        query: &Message,
        request_wire: &[u8],
        deadline: time::Instant,
    ) -> Result<Message, TransportError> {
        let (method, uri) = request_uri(&self.config, request_wire)?;
        let transaction_authenticated = has_tsig(query);
        let mut builder = Request::builder()
            .method(match method {
                DohMethod::Get => Method::GET,
                DohMethod::Post => Method::POST,
            })
            .uri(uri)
            .header(header::ACCEPT, DOH_MEDIA_TYPE);
        if transaction_authenticated {
            builder = builder.header(header::CACHE_CONTROL, "no-store, no-cache");
        }
        if method == DohMethod::Post {
            builder = builder.header(header::CONTENT_TYPE, DOH_MEDIA_TYPE);
        }
        let request = builder
            .body(())
            .map_err(|_| TransportError::InvalidHttpProtocol("cannot build DoH request"))?;

        let (response, mut body) = {
            let mut ready = time::timeout_at(deadline, session.as_ref().clone().ready())
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(http_io_error)?;
            let end_stream = method == DohMethod::Get;
            let (response, mut stream) = ready
                .send_request(request, end_stream)
                .map_err(http_io_error)?;
            if !end_stream {
                stream
                    .send_data(Bytes::copy_from_slice(request_wire), true)
                    .map_err(http_io_error)?;
            }
            let response = time::timeout_at(deadline, response)
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(http_io_error)?;
            let (parts, body) = response.into_parts();
            (parts, body)
        };

        if !response.status.is_success() {
            return Err(TransportError::InvalidHttpProtocol(
                "server returned a non-success HTTP status",
            ));
        }
        let content_type = response
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .ok_or(TransportError::InvalidHttpProtocol(
                "response is missing Content-Type",
            ))?;
        if !content_type.eq_ignore_ascii_case(DOH_MEDIA_TYPE) {
            return Err(TransportError::InvalidHttpProtocol(
                "response Content-Type is not application/dns-message",
            ));
        }
        let response_wire = receive_body(&mut body, deadline).await?;
        let mut message = Message::from_wire(&response_wire).map_err(TransportError::decode)?;
        if !message.headers.qr
            || message.headers.opcode != query.headers.opcode
            || message.headers.id != query.headers.id
            || !crate::message::response_questions_match(&message, query)
        {
            return Err(TransportError::InvalidHttpProtocol(
                "DNS response does not match the request",
            ));
        }
        if !has_tsig(&message) {
            let age = match response.headers.get(header::AGE) {
                Some(value) => parse_age(value).ok_or(TransportError::InvalidHttpProtocol(
                    "response Age header is malformed",
                ))?,
                None => 0,
            };
            apply_age(&mut message, age);
        }
        Ok(message)
    }
}

impl Transport for DohTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Https)
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
            let original_id = query.headers.id;
            let query = prepared_query(query)?;
            let request_wire = query.into_wire().map_err(TransportError::encode)?;
            let deadline = checked_deadline(timeout)?;
            for retry in 0..=1 {
                let session = self.connect(server, deadline).await?;
                let result = self
                    .exchange_once(&session, &query, &request_wire, deadline)
                    .await;
                if result.is_err() {
                    self.evict(server, &session);
                }
                if retry == 0 && matches!(result, Err(TransportError::Io(_))) {
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

fn http_io_error(error: h2::Error) -> TransportError {
    TransportError::Io(io::Error::other(error))
}

#[cfg(test)]
mod tests;

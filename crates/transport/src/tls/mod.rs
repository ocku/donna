//! DNS over TLS (DoT) and zone transfer over TLS (XoT).
//!
//! The built-in configurations deliberately negotiate TLS 1.3 only and offer
//! the `dot` ALPN token. Ordinary DoT also interoperates with RFC 7858 peers
//! that do not negotiate ALPN. Clients authenticate an explicit DNS name,
//! never the socket address supplied to [`crate::Transport::exchange`].

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ResolvesServerCert, danger::ClientCertVerifier},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream as ServerTlsStream};
use tracing::instrument;

use crate::{DnsRequestHandler, TransportError, TransportServer, tcp};

mod client;

pub use client::{TlsClientConfig, TlsClientConfigError, TlsTransport};

/// The IANA-assigned port for DNS over TLS.
pub const DOT_PORT: u16 = 853;
/// The ALPN protocol identifier used by DoT and XoT.
pub const DOT_ALPN: &[u8] = b"dot";

const MAX_CONCURRENT_TLS_CONNECTIONS: usize = 256;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A TLS 1.3-only DNS server configuration.
#[derive(Clone)]
pub struct TlsServerConfig(Arc<ServerConfig>, bool);

impl std::fmt::Debug for TlsServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("TlsServerConfig").finish()
    }
}

impl TlsServerConfig {
    /// Builds a server that authenticates itself but does not request a client
    /// certificate. This is suitable for ordinary DoT.
    pub fn new(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, rustls::Error> {
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)?;
        Self::finish(config, false)
    }

    /// Builds a server that requires and authorizes client certificates.
    ///
    /// This is the preferred RFC 9103 XoT authentication mode. The supplied
    /// verifier is responsible for restricting transfer clients to identities
    /// authorized by the operator.
    pub fn with_client_verifier(
        verifier: Arc<dyn ClientCertVerifier>,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, rustls::Error> {
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificate_chain, private_key)?;
        Self::finish(config, true)
    }

    /// Builds a server around an operator-supplied certificate resolver.
    ///
    /// This is the entry point for RFC 7250 raw public keys: use Rustls's
    /// `AlwaysResolvesServerRawPublicKeys` resolver. Client authentication is
    /// disabled, so XoT deployments should prefer [`Self::with_client_verifier`]
    /// unless another layer supplies RFC 9103 authorization.
    pub fn with_certificate_resolver(
        resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, rustls::Error> {
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        Self::finish(config, false)
    }

    /// Builds an mTLS server around an operator-supplied certificate resolver.
    ///
    /// Combining an authorizing client verifier with Rustls's raw-public-key
    /// resolver supports mutually authenticated XoT without X.509 server
    /// certificates.
    pub fn with_client_verifier_and_certificate_resolver(
        verifier: Arc<dyn ClientCertVerifier>,
        resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, rustls::Error> {
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);
        Self::finish(config, true)
    }

    fn finish(mut config: ServerConfig, require_dot_alpn: bool) -> Result<Self, rustls::Error> {
        config.alpn_protocols = vec![DOT_ALPN.to_vec()];
        // RFC 8310 requires TLS session resumption without server-side state.
        // Disable the default stateful cache and rotate encrypted tickets.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.ticketer = rustls::crypto::ring::Ticketer::new()?;
        Ok(Self(Arc::new(config), require_dot_alpn))
    }
}

fn validate_server_session(
    stream: &ServerTlsStream<TcpStream>,
    require_dot_alpn: bool,
) -> Result<(), TransportError> {
    let (_, connection) = stream.get_ref();
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(TransportError::InvalidTlsProtocol(
            "TLS 1.3 was not negotiated",
        ));
    }
    validate_dot_alpn(connection.alpn_protocol(), require_dot_alpn)
}

fn validate_dot_alpn(
    negotiated: Option<&[u8]>,
    require_dot_alpn: bool,
) -> Result<(), TransportError> {
    match negotiated {
        Some(DOT_ALPN) => Ok(()),
        None if !require_dot_alpn => Ok(()),
        Some(_) | None => Err(TransportError::InvalidTlsProtocol(
            "an incompatible ALPN protocol was negotiated",
        )),
    }
}

/// Serves DNS-over-TLS requests on a dedicated listener.
#[derive(Debug, Clone)]
pub struct TlsTransportServer {
    config: TlsServerConfig,
}

impl TlsTransportServer {
    /// Creates a DNS-over-TLS server from a strict TLS configuration.
    pub fn new(config: TlsServerConfig) -> Self {
        Self { config }
    }
}

impl TransportServer for TlsTransportServer {
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
            let require_dot_alpn = self.config.1;
            let acceptor = TlsAcceptor::from(self.config.0);
            let handler = Arc::new(handler);
            let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_TLS_CONNECTIONS));
            loop {
                let permit = Arc::clone(&permits)
                    .acquire_owned()
                    .await
                    .map_err(|_| io::Error::other("TLS admission semaphore closed"))?;
                let (stream, peer) = crate::listener_io::accept(&listener).await?;
                let acceptor = acceptor.clone();
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let _permit = permit;
                    let stream =
                        match time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                tracing::debug!(%peer, ?error, "TLS handshake failed");
                                return;
                            }
                            Err(_) => {
                                tracing::debug!(%peer, "TLS handshake timed out");
                                return;
                            }
                        };
                    if validate_server_session(&stream, require_dot_alpn).is_err() {
                        tracing::debug!(%peer, "rejecting incompatible TLS session");
                        return;
                    }
                    let transfers_allowed = stream.get_ref().1.alpn_protocol() == Some(DOT_ALPN);
                    tcp::serve_tls_connection(stream, peer, handler, transfers_allowed).await;
                });
            }
        })
    }
}

#[cfg(test)]
mod tests;

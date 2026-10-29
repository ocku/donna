//! TLS authentication and QUIC transport parameters for DNS over QUIC.

use std::{sync::Arc, time::Duration};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName},
};

use super::DOQ_ALPN;

const MAX_CONCURRENT_STREAMS: u32 = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Reports invalid DoQ TLS or QUIC configuration.
#[derive(Debug)]
pub enum DoqConfigError {
    /// The TLS authentication name is not a valid DNS name.
    InvalidAuthenticationName(InvalidDnsNameError),
    /// Rustls rejected the certificate or private key.
    Tls(rustls::Error),
    /// QUIC rejected a transport parameter.
    Transport(&'static str),
    /// The TLS provider cannot supply QUIC's initial cipher suite.
    QuicCrypto(String),
}

impl std::fmt::Display for DoqConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAuthenticationName(error) => error.fmt(formatter),
            Self::Tls(error) => error.fmt(formatter),
            Self::Transport(reason) => write!(formatter, "invalid DoQ transport: {reason}"),
            Self::QuicCrypto(reason) => write!(formatter, "invalid DoQ crypto: {reason}"),
        }
    }
}

impl std::error::Error for DoqConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAuthenticationName(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Transport(_) | Self::QuicCrypto(_) => None,
        }
    }
}

/// Strict TLS 1.3 client configuration for DoQ.
#[derive(Clone)]
pub struct DoqClientConfig {
    pub(super) quic: quinn::ClientConfig,
    pub(super) authentication_name: String,
}

impl std::fmt::Debug for DoqClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DoqClientConfig")
            .field("authentication_name", &self.authentication_name)
            .finish_non_exhaustive()
    }
}

impl DoqClientConfig {
    /// Builds a DoQ client that authenticates `authentication_name` against
    /// `root_certificates` and negotiates only the `doq` ALPN token.
    pub fn new(
        root_certificates: RootCertStore,
        authentication_name: String,
    ) -> Result<Self, DoqConfigError> {
        ServerName::try_from(authentication_name.clone())
            .map_err(DoqConfigError::InvalidAuthenticationName)?;
        let mut tls = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_certificates)
            .with_no_client_auth();
        tls.alpn_protocols = vec![DOQ_ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| DoqConfigError::QuicCrypto(error.to_string()))?;
        let mut quic = quinn::ClientConfig::new(Arc::new(crypto));
        // Only clients initiate DoQ transactions. Advertising zero prevents
        // servers from opening bidirectional application streams to the client.
        quic.transport_config(transport_config(0)?);
        Ok(Self {
            quic,
            authentication_name,
        })
    }
}

/// TLS 1.3 and QUIC transport configuration for a DoQ server.
#[derive(Clone)]
pub struct DoqServerConfig(pub(super) quinn::ServerConfig);

impl std::fmt::Debug for DoqServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("DoqServerConfig").finish()
    }
}

impl DoqServerConfig {
    /// Builds a DoQ server with an authenticated certificate and no 0-RTT.
    pub fn new(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, DoqConfigError> {
        let mut tls = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .map_err(DoqConfigError::Tls)?;
        tls.alpn_protocols = vec![DOQ_ALPN.to_vec()];
        tls.max_early_data_size = 0;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|error| DoqConfigError::QuicCrypto(error.to_string()))?;
        let mut quic = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        quic.transport = transport_config(MAX_CONCURRENT_STREAMS)?;
        Ok(Self(quic))
    }
}

pub(super) fn transport_config(
    incoming_queries: u32,
) -> Result<Arc<quinn::TransportConfig>, DoqConfigError> {
    let mut transport = quinn::TransportConfig::default();
    // RFC 9250 section 5.4 requires traffic-analysis protection for every
    // transaction. EDNS padding alone cannot cover non-EDNS peers, signed
    // messages, or messages that already fill the DNS framing budget. Pad
    // application datagrams in both directions without rewriting DNS bytes.
    transport.pad_to_mtu(true);
    transport.max_concurrent_uni_streams(0_u8.into());
    transport.max_concurrent_bidi_streams(incoming_queries.into());
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .map_err(|_| DoqConfigError::Transport("idle timeout is out of range"))?,
    ));
    Ok(Arc::new(transport))
}

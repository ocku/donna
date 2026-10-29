use std::sync::Arc;

use rustls::{
    ClientConfig, RootCertStore,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName},
};

use crate::tls::DOT_ALPN;

/// A strict DNS-over-TLS client configuration.
#[derive(Clone)]
pub struct TlsClientConfig {
    pub(in crate::tls) config: Arc<ClientConfig>,
    pub(in crate::tls) authentication_name: ServerName<'static>,
}

impl std::fmt::Debug for TlsClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsClientConfig")
            .field("authentication_name", &self.authentication_name)
            .finish_non_exhaustive()
    }
}

impl TlsClientConfig {
    /// Builds a TLS 1.3-only client that authenticates `authentication_name`
    /// against `root_certificates` and offers only the `dot` ALPN token.
    pub fn new(
        root_certificates: RootCertStore,
        authentication_name: String,
    ) -> Result<Self, InvalidDnsNameError> {
        let authentication_name = ServerName::try_from(authentication_name)?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_certificates)
            .with_no_client_auth();
        config.alpn_protocols = vec![DOT_ALPN.to_vec()];
        Ok(Self {
            config: Arc::new(config),
            authentication_name,
        })
    }

    /// Builds a TLS 1.3-only client with a certificate and key for mutual TLS.
    ///
    /// XoT deployments can use this with a server-side verifier that authorizes
    /// the presented secondary certificate.
    pub fn with_client_auth(
        root_certificates: RootCertStore,
        authentication_name: String,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, TlsClientConfigError> {
        let authentication_name = ServerName::try_from(authentication_name)
            .map_err(TlsClientConfigError::InvalidAuthenticationName)?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_certificates)
            .with_client_auth_cert(certificate_chain, private_key)
            .map_err(TlsClientConfigError::Tls)?;
        config.alpn_protocols = vec![DOT_ALPN.to_vec()];
        Ok(Self {
            config: Arc::new(config),
            authentication_name,
        })
    }

    /// Builds a TLS 1.3-only client using an operator-supplied verifier.
    ///
    /// This supports RFC 8310 SPKI pin sets and RFC 7250 raw public keys without
    /// weakening the transport's TLS-version or ALPN policy. A raw-public-key
    /// verifier must return `true` from
    /// [`ServerCertVerifier::requires_raw_public_keys`].
    pub fn with_server_verifier(
        verifier: Arc<dyn ServerCertVerifier>,
        authentication_name: String,
    ) -> Result<Self, InvalidDnsNameError> {
        let authentication_name = ServerName::try_from(authentication_name)?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = vec![DOT_ALPN.to_vec()];
        Ok(Self {
            config: Arc::new(config),
            authentication_name,
        })
    }

    /// Builds a pinned/raw-public-key client that also presents an mTLS identity.
    ///
    /// This combines the RFC 8310 verifier hook with RFC 9103's preferred XoT
    /// client authorization mechanism.
    pub fn with_server_verifier_and_client_auth(
        verifier: Arc<dyn ServerCertVerifier>,
        authentication_name: String,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, TlsClientConfigError> {
        let authentication_name = ServerName::try_from(authentication_name)
            .map_err(TlsClientConfigError::InvalidAuthenticationName)?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(certificate_chain, private_key)
            .map_err(TlsClientConfigError::Tls)?;
        config.alpn_protocols = vec![DOT_ALPN.to_vec()];
        Ok(Self {
            config: Arc::new(config),
            authentication_name,
        })
    }
}

/// A DNS-over-TLS client configuration error.
#[derive(Debug)]
pub enum TlsClientConfigError {
    /// The authentication domain name is not a valid TLS server name.
    InvalidAuthenticationName(InvalidDnsNameError),
    /// Rustls rejected the certificate chain or private key.
    Tls(rustls::Error),
}

impl std::fmt::Display for TlsClientConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAuthenticationName(error) => error.fmt(formatter),
            Self::Tls(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TlsClientConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAuthenticationName(error) => Some(error),
            Self::Tls(error) => Some(error),
        }
    }
}

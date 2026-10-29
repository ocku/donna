use super::{config::Listener, net, server::Handler};
use anyhow::{Context, Result};
use dns::DomainName;
use std::{net::SocketAddr, path::Path};
use tokio::task::JoinSet;
use transport::*;

pub(super) enum PreparedListener {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls(SocketAddr, TlsTransportServer),
    Https(SocketAddr, DohTransportServer),
    Quic(SocketAddr, DoqTransportServer),
    CryptUdp(SocketAddr, DnscryptUdpTransportServer),
    CryptTcp(SocketAddr, DnscryptTransportServer),
}

impl PreparedListener {
    pub(super) fn start(self, tasks: &mut JoinSet<std::io::Result<()>>, handler: Handler) {
        tasks.spawn(async move {
            match self {
                Self::Udp(a) => UdpTransport.serve(a, handler).await,
                Self::Tcp(a) => TcpTransport.serve(a, handler).await,
                Self::Tls(a, t) => t.serve(a, handler).await,
                Self::Https(a, t) => t.serve(a, handler).await,
                Self::Quic(a, t) => t.serve(a, handler).await,
                Self::CryptUdp(a, t) => t.serve(a, handler).await,
                Self::CryptTcp(a, t) => t.serve(a, handler).await,
            }
        });
    }
}

pub(super) fn prepare(config: &Listener, base: &Path) -> Result<PreparedListener> {
    let address = config.address();
    let identity = |certificate: &Path, private_key: &Path| {
        Ok::<_, anyhow::Error>((
            net::certificates(&base.join(certificate))?,
            net::private_key(&base.join(private_key))?,
        ))
    };
    Ok(match config {
        Listener::Udp { .. } => PreparedListener::Udp(address),
        Listener::Tcp { .. } => PreparedListener::Tcp(address),
        Listener::Tls {
            certificate,
            private_key,
            ..
        } => {
            let (chain, key) = identity(certificate, private_key)?;
            PreparedListener::Tls(
                address,
                TlsTransportServer::new(TlsServerConfig::new(chain, key)?),
            )
        }
        Listener::Https {
            certificate,
            private_key,
            https_path,
            ..
        } => {
            let (chain, key) = identity(certificate, private_key)?;
            PreparedListener::Https(
                address,
                DohTransportServer::new(DohServerConfig::new(chain, key, https_path.clone())?),
            )
        }
        Listener::Quic {
            certificate,
            private_key,
            ..
        } => {
            let (chain, key) = identity(certificate, private_key)?;
            PreparedListener::Quic(
                address,
                DoqTransportServer::new(DoqServerConfig::new(chain, key)?),
            )
        }
        Listener::DnscryptUdp {
            provider_name,
            provider_key,
            dnscrypt_certificate,
            dnscrypt_secret_key,
            ..
        }
        | Listener::DnscryptTcp {
            provider_name,
            provider_key,
            dnscrypt_certificate,
            dnscrypt_secret_key,
            ..
        } => {
            let crypt = dnscrypt(
                base,
                provider_name,
                provider_key,
                dnscrypt_certificate,
                dnscrypt_secret_key,
            )?;
            match config {
                Listener::DnscryptUdp { .. } => {
                    PreparedListener::CryptUdp(address, DnscryptUdpTransportServer::new(crypt))
                }
                _ => PreparedListener::CryptTcp(address, DnscryptTransportServer::new(crypt)),
            }
        }
    })
}

fn dnscrypt(
    base: &Path,
    provider_name: &str,
    provider_key: &str,
    certificate_path: &Path,
    secret_path: &Path,
) -> Result<DnscryptServerConfig> {
    let provider = net::key32(provider_key)?;
    let bytes = std::fs::read(base.join(certificate_path)).context("read DNSCrypt certificate")?;
    let secret =
        std::fs::read_to_string(base.join(secret_path)).context("read DNSCrypt secret key")?;
    let now = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    let certificate = DnscryptCertificate::verify(&bytes, &provider, now)?;
    Ok(DnscryptServerConfig::new(
        DomainName::from_dotted(provider_name)?,
        vec![DnscryptResolverIdentity::new(
            certificate,
            net::key32(secret.trim())?,
        )?],
    )?)
}

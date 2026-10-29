//! DNSCrypt v2 Box-XChaChaPoly over TCP and UDP.
//!
//! Each encrypted query uses a fresh TCP connection and the connection closes
//! after one response. UDP exchanges are bounded by their query size and retry
//! authenticated truncated responses over TCP. Resolver certificates are
//! fetched with an ordinary TXT query, authenticated by a provisioned Ed25519
//! provider key, and refreshed at most hourly or when they expire.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crypto_box::{
    ChaChaBox, PublicKey, SecretKey,
    aead::{Aead, generic_array::GenericArray},
};
use dns::{FromWire, IntoWire, Message};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Semaphore},
    time,
};
use tracing::instrument;

use crate::{
    DnsRequest, DnsRequestHandler, DnsResponse, Transport, TransportError, TransportProtocol,
    TransportServer, authenticated_response_headers_match, checked_deadline, has_tsig,
    normalize_response_headers, request_questions_are_safe_to_echo, same_questions,
    tcp::{matches_tcp_query, write_frame},
    truncate_response,
};

/// The conventional TCP and UDP port used by DNSCrypt.
pub const DNSCRYPT_PORT: u16 = 443;

const CERT_MAGIC: &[u8; 4] = b"DNSC";
const ES_VERSION: [u8; 2] = [0, 2];
const MINOR_VERSION: [u8; 2] = [0, 0];
const RESOLVER_MAGIC: [u8; 8] = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
const RESUME_MAGIC: [u8; 8] = *b"PQResume";
const CERTIFICATE_MIN_LENGTH: usize = 124;
const QUERY_HEADER_LENGTH: usize = 8 + 32 + 12;
const RESPONSE_HEADER_LENGTH: usize = 8 + 24;
const TAG_LENGTH: usize = 16;
const MAX_PACKET_LENGTH: usize = 4096;
const MAX_QUERY_PLAINTEXT: usize = MAX_PACKET_LENGTH - QUERY_HEADER_LENGTH - TAG_LENGTH;
// The draft requires encrypted responses to be strictly smaller than 4096.
const MAX_RESPONSE_PLAINTEXT: usize = MAX_PACKET_LENGTH - 1 - RESPONSE_HEADER_LENGTH - TAG_LENGTH;
const CERTIFICATE_REFRESH: Duration = Duration::from_secs(60 * 60);
const CERTIFICATE_UDP_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const SERVER_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Independent uniformly random 96-bit nonces reveal no counter or stable
/// prefix. The first nonce is generated at construction so entropy failures
/// are reported immediately; later nonces use the operating system CSPRNG.
/// The counter bounds usage and remains exhausted rather than wrapping.
#[derive(Debug)]
struct NonceSequence {
    seed: [u8; 12],
    generated: AtomicU64,
    #[cfg(test)]
    deterministic: bool,
}

impl NonceSequence {
    fn random() -> Result<Self, getrandom::Error> {
        let mut seed = [0; 12];
        getrandom::fill(&mut seed)?;
        Ok(Self {
            seed,
            generated: AtomicU64::new(0),
            #[cfg(test)]
            deterministic: false,
        })
    }

    #[cfg(test)]
    fn deterministic(prefix: [u8; 4]) -> Self {
        let mut seed = [0; 12];
        seed[..4].copy_from_slice(&prefix);
        Self {
            seed,
            generated: AtomicU64::new(0),
            deterministic: true,
        }
    }

    #[allow(deprecated, reason = "Retain the atomic API supported by Rust 1.88.")]
    fn next(&self) -> Option<[u8; 12]> {
        loop {
            let generated = self
                .generated
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
                    counter.checked_add(1)
                })
                .ok()?;
            let mut nonce = self.seed;
            #[cfg(test)]
            if self.deterministic {
                nonce[4..].copy_from_slice(&generated.to_be_bytes());
                if nonce != [0; 12] {
                    return Some(nonce);
                }
                continue;
            }
            if generated != 0 {
                getrandom::fill(&mut nonce).ok()?;
            }
            if nonce != [0; 12] {
                return Some(nonce);
            }
        }
    }
}

/// Reports invalid DNSCrypt key, certificate, or provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnscryptConfigError {
    /// The provider public key is not a valid Ed25519 key.
    InvalidProviderKey,
    /// A resolver certificate is malformed, unsupported, expired, or has a bad signature.
    InvalidCertificate(&'static str),
    /// A certificate's resolver public key does not match its secret key.
    ResolverKeyMismatch,
    /// The provider name cannot be extended with the standard DNSCrypt labels.
    InvalidProviderName,
}

impl std::fmt::Display for DnscryptConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProviderKey => formatter.write_str("invalid Ed25519 provider public key"),
            Self::InvalidCertificate(reason) => {
                write!(formatter, "invalid DNSCrypt certificate: {reason}")
            }
            Self::ResolverKeyMismatch => {
                formatter.write_str("resolver secret key does not match its certificate")
            }
            Self::InvalidProviderName => formatter.write_str("invalid DNSCrypt provider name"),
        }
    }
}

impl std::error::Error for DnscryptConfigError {}

mod certificate;
mod client;
mod crypto;
mod server;

pub use certificate::{DnscryptCertificate, DnscryptClientConfig};
pub use client::{DnscryptTransport, DnscryptUdpTransport};
pub use server::{
    DnscryptResolverIdentity, DnscryptServerConfig, DnscryptTransportServer,
    DnscryptUdpTransportServer,
};

use crypto::*;

#[cfg(test)]
use client::{certificate_query, padded_certificate_query, select_certificate};
#[cfg(test)]
use server::{serve_connection, serve_datagram};

async fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, io::Error> {
    let length = usize::from(stream.read_u16().await?);
    if length > MAX_PACKET_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNSCrypt packet exceeds 4096 bytes",
        ));
    }
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet).await?;
    Ok(packet)
}

fn unix_time() -> Result<u32, TransportError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TransportError::InvalidDnscryptProtocol("system time precedes Unix epoch"))?
        .as_secs();
    u32::try_from(seconds).map_err(|_| {
        TransportError::InvalidDnscryptProtocol("system time exceeds DNSCrypt timestamp range")
    })
}

#[cfg(test)]
mod tests;

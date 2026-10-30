//! Application-owned DNS policy composed with Donna's forwarding resolver.

use std::{collections::HashSet, env, net::SocketAddr, sync::Arc, time::Duration};

use dns::{DomainName, Edns, ExtendedDnsError, ExtendedDnsErrorCode, Message, RCode};
use resolver::{Forwarder, ForwarderConfig};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use transport::{
    BoxFuture, DoqClientConfig, DoqTransport, TcpTransport, Transport, TransportError,
    TransportServer, UdpTransport,
};

type Failure = Box<dyn std::error::Error + Send + Sync>;

const DEFAULT_UPSTREAM_ADDRS: &str = "9.9.9.9:853,149.112.112.112:853";

fn parse_upstreams(value: &str) -> Result<Vec<SocketAddr>, Failure> {
    let mut upstreams = Vec::new();

    for entry in value.split(',') {
        let address = entry.trim().parse()?;

        if !upstreams.contains(&address) {
            upstreams.push(address);
        }
    }

    if upstreams.len() < 2 {
        return Err("UPSTREAM_ADDRS must contain at least two distinct IP:port addresses".into());
    }

    Ok(upstreams)
}

struct Blocklist(HashSet<DomainName>);

impl Blocklist {
    fn parse(text: &str) -> Result<Self, Failure> {
        let mut names = HashSet::new();

        for (index, line) in text.lines().enumerate() {
            let entry = line.split('#').next().unwrap_or_default().trim();

            if entry.is_empty() {
                continue;
            }

            // Accept plain ASCII DNS names, including punycode and an optional
            // root dot. Reject hosts/dnsmasq/adblock syntax instead of silently
            // loading a list that will never match. The root cannot be blocked.
            if entry == "."
                || !entry
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            {
                return Err(format!("blocklist line {}: expected a domain name", index + 1).into());
            }

            let name = DomainName::from_dotted(entry)
                .map_err(|error| format!("blocklist line {}: {error}", index + 1))?;

            names.insert(name);
        }

        if names.is_empty() {
            return Err("blocklist contains no domains".into());
        }

        Ok(Self(names))
    }

    fn contains(&self, name: &DomainName) -> bool {
        let labels = name.as_ref();

        // Hash each ancestor, never scan the entire blocklist. DomainName's
        // equality and hashing are case insensitive and preserve label boundaries.
        (0..labels.len()).any(|start| {
            let ancestor = DomainName::from_labels(labels[start..].to_vec())
                .expect("a suffix of a valid DNS name is valid");

            self.0.contains(&ancestor)
        })
    }
}

fn blocked_response(query: &Message) -> Message {
    let mut response = query.error_response(RCode::NameError, true);

    if let Some(record) = response.additionals.first_mut() {
        let mut edns =
            Edns::try_from_record(record).expect("error_response creates a valid OPT record");

        edns.push_extended_dns_error(ExtendedDnsError::without_text(
            ExtendedDnsErrorCode::Blocked,
        ))
        .expect("Blocked is a canonical EDE code");

        *record = edns.into_record();
    }

    response
}

struct BlockingTransport<T> {
    blocklist: Arc<Blocklist>,
    upstream: T,
}

impl<T: Transport> Transport for BlockingTransport<T> {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            // Forwarder validates requests before calling this transport, so
            // malformed queries and unsupported operations retain its policy.
            let blocked = query
                .questions
                .iter()
                .any(|question| self.blocklist.contains(&question.qname));

            if blocked {
                return Ok(blocked_response(query));
            }

            self.upstream.exchange(server, query, timeout).await
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let listen: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:5353".into())
        .parse()?;

    let upstreams = parse_upstreams(
        &env::var("UPSTREAM_ADDRS").unwrap_or_else(|_| DEFAULT_UPSTREAM_ADDRS.into()),
    )?;
    let server_name = env::var("UPSTREAM_SERVER_NAME").unwrap_or_else(|_| "dns.quad9.net".into());
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Ok(file) = env::var("UPSTREAM_CA_FILE") {
        let certificates = CertificateDer::pem_file_iter(file)?.collect::<Result<Vec<_>, _>>()?;

        if certificates.is_empty() {
            return Err("UPSTREAM_CA_FILE contains no certificates".into());
        }

        for certificate in certificates {
            roots.add(certificate)?;
        }
    }

    let file = env::var("BLOCKLIST_FILE")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/blocklist.txt").into());

    let blocklist = Arc::new(Blocklist::parse(&std::fs::read_to_string(file)?)?);

    println!(
        "Ad blocker: {} domains and their subdomains; UDP/TCP {listen}; upstreams DoQ {upstreams:?}, TLS name {server_name}",
        blocklist.0.len()
    );

    // Authenticate each QUIC upstream using the configured TLS name, while
    // connecting directly to its IP to avoid a bootstrap DNS lookup. Forwarder
    // owns validation, caching, retries and failover. Share one blocklist.
    let peers = upstreams
        .into_iter()
        .map(|address| {
            let upstream =
                DoqTransport::new(DoqClientConfig::new(roots.clone(), server_name.clone())?);
            let transport = BlockingTransport {
                blocklist: Arc::clone(&blocklist),
                upstream,
            };

            Ok((address, transport))
        })
        .collect::<Result<Vec<_>, Failure>>()?;

    let forwarder = Arc::new(Forwarder::new(peers, ForwarderConfig::default()));

    let handler = move |query: Message| {
        let forwarder = Arc::clone(&forwarder);

        async move { forwarder.answer_message(&query).await }
    };

    tokio::try_join!(
        UdpTransport.serve(listen, handler.clone()),
        TcpTransport.serve(listen, handler)
    )?;

    Ok(())
}

#[cfg(test)]
mod tests;

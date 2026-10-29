use super::cli::{EndpointArgs, Protocol};
use super::constants::HEX_KEY_BYTES;
use anyhow::{Context, Result, bail};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use transport::*;

pub fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(
        File::open(path).with_context(|| format!("open {}", path.display()))?,
    ))
    .collect::<std::io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        bail!("{} contains no PEM certificates", path.display());
    }
    Ok(certs)
}

pub fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(
        File::open(path).with_context(|| format!("open {}", path.display()))?,
    ))?
    .context("PEM file contains no private key")
}

pub fn key32(value: &str) -> Result<[u8; HEX_KEY_BYTES]> {
    let value: String = value.chars().filter(|c| *c != ':').collect();
    if value.len() != HEX_KEY_BYTES * 2 || !value.is_ascii() {
        bail!("key must contain 64 hexadecimal digits");
    }
    let mut key = [0; HEX_KEY_BYTES];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .context("invalid hexadecimal key")?;
    }
    Ok(key)
}

pub enum Client {
    Udp,
    Tcp,
    Tls(TlsTransport),
    Https(DohTransport),
    Quic(DoqTransport),
    DnscryptUdp(DnscryptUdpTransport),
    DnscryptTcp(DnscryptTransport),
}

impl Client {
    pub fn transport(&self) -> &dyn Transport {
        match self {
            Self::Udp => &UdpTransport,
            Self::Tcp => &TcpTransport,
            Self::Tls(client) => client,
            Self::Https(client) => client,
            Self::Quic(client) => client,
            Self::DnscryptUdp(client) => client,
            Self::DnscryptTcp(client) => client,
        }
    }

    pub async fn exchange(
        &self,
        address: SocketAddr,
        query: &dns::Message,
        timeout: Duration,
    ) -> Result<dns::Message> {
        if query
            .questions
            .first()
            .is_some_and(|q| q.qtype == dns::QueryType::AXFR)
        {
            let answers = match self {
                Self::Tcp => TcpTransport.transfer(address, query, timeout).await?,
                Self::Tls(client) => client.transfer(address, query, timeout).await?,
                Self::Quic(client) => client.transfer(address, query, timeout).await?,
                _ => bail!("AXFR requires TCP, TLS, or QUIC"),
            };
            return Ok(dns::Message {
                headers: dns::Headers {
                    qr: true,
                    aa: true,
                    ..query.headers.clone()
                },
                questions: query.questions.clone(),
                answers,
                authorities: vec![],
                additionals: vec![],
            });
        }
        Ok(self.transport().exchange(address, query, timeout).await?)
    }
}

impl Transport for Client {
    fn protocol(&self) -> Option<TransportProtocol> {
        self.transport().protocol()
    }

    fn transition(&self, reason: TransitionReason) -> Option<&dyn Transport> {
        self.transport().transition(reason)
    }

    fn exchange<'a>(
        &'a self,
        address: SocketAddr,
        query: &'a dns::Message,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<dns::Message, TransportError>> {
        self.transport().exchange(address, query, timeout)
    }
}

pub fn client(args: &EndpointArgs, port: u16) -> Result<Client> {
    let roots = || -> Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &args.ca {
            for cert in certificates(path)? {
                roots.add(cert)?;
            }
        }
        Ok(roots)
    };
    let name = || {
        args.tls_name
            .clone()
            .context("TLS transports require tls_name / --tls-name")
    };
    Ok(match args.protocol {
        Protocol::Udp => Client::Udp,
        Protocol::Tcp => Client::Tcp,
        Protocol::Tls => Client::Tls(TlsTransport::new(TlsClientConfig::new(roots()?, name()?)?)),
        Protocol::Https => Client::Https(DohTransport::new(DohClientConfig::new(
            roots()?,
            name()?,
            args.https_authority
                .clone()
                .unwrap_or(format!("{}:{port}", name()?)),
            args.https_path.clone(),
            if args.https_get {
                DohMethod::Get
            } else {
                DohMethod::Post
            },
        )?)),
        Protocol::Quic => Client::Quic(DoqTransport::new(DoqClientConfig::new(roots()?, name()?)?)),
        Protocol::DnscryptUdp | Protocol::DnscryptTcp => {
            let config = DnscryptClientConfig::with_provider_name(
                dns::DomainName::from_dotted(
                    args.provider_name
                        .as_deref()
                        .context("DNSCrypt requires provider_name / --provider-name")?,
                )?,
                key32(
                    args.provider_key
                        .as_deref()
                        .context("DNSCrypt requires provider_key / --provider-key")?,
                )?,
            )?;
            match args.protocol {
                Protocol::DnscryptUdp => Client::DnscryptUdp(DnscryptUdpTransport::new(config)?),
                _ => Client::DnscryptTcp(DnscryptTransport::new(config)?),
            }
        }
    })
}

pub async fn address(server: &str, port: u16) -> Result<SocketAddr> {
    let server = server.strip_prefix('@').unwrap_or(server);
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let host = if server.contains(':') {
        server.to_owned()
    } else {
        format!("{server}:{port}")
    };
    tokio::net::lookup_host(&host)
        .await
        .with_context(|| format!("resolve DNS server {host}"))?
        .next()
        .context("DNS server has no addresses")
}

pub fn system_servers() -> Result<Vec<String>> {
    let contents = std::fs::read_to_string("/etc/resolv.conf")
        .context("read /etc/resolv.conf; supply --server explicitly")?;
    let servers: Vec<_> = contents
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver")
                .then(|| words.next().map(str::to_owned))
                .flatten()
        })
        .collect();
    if servers.is_empty() {
        bail!("no nameservers in /etc/resolv.conf; supply --server");
    }
    Ok(servers)
}

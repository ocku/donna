use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use crypto_box::SecretKey;
use dns::{DomainName, TsigAlgorithm, TsigKey, master::MasterFile};
mod fixtures;
use fixtures::{PROVIDER_SECRET, RESOLVER_SECRET, certificate, private_key};
type Failure = Box<dyn std::error::Error + Send + Sync>;
use nameserver::{NameServer, NameServerConfig, Zone};
use transport::{
    DnscryptCertificate, DnscryptResolverIdentity, DnscryptServerConfig, DnscryptTransportServer,
    DnscryptUdpTransportServer, DohServerConfig, DohTransportServer, DoqServerConfig,
    DoqTransportServer, TcpTransport, TlsServerConfig, TlsTransportServer, TransportServer,
    UdpTransport,
};

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let host = env::var("LISTEN_HOST").unwrap_or("127.0.0.1".into());
    let directory = PathBuf::from(env::var("CERT_DIR").unwrap_or("/certs".into()));
    let zone_path = env::var("ZONE_FILE")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/zone.db").into());
    let apex = DomainName::from_dotted("example.test.")?;
    let master = MasterFile::parse(&std::fs::read_to_string(zone_path)?, Some(apex.clone()))?;
    let server = NameServer::with_config(NameServerConfig {
        allow_axfr_to: vec![(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        )],
        tsig_keys: vec![TsigKey::new(
            DomainName::from_dotted("interop-key.")?,
            TsigAlgorithm::HmacSha256,
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )?],
        ..NameServerConfig::default()
    });
    server.install(Zone::from_master(apex, master)?).await?;
    let tls = TlsTransportServer::new(TlsServerConfig::new(
        vec![certificate(&directory)?],
        private_key(&directory)?,
    )?);
    let doh = DohTransportServer::new(DohServerConfig::new(
        vec![certificate(&directory)?],
        private_key(&directory)?,
        "/dns-query".into(),
    )?);
    let doq = DoqTransportServer::new(DoqServerConfig::new(
        vec![certificate(&directory)?],
        private_key(&directory)?,
    )?);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as u32;
    let public = *SecretKey::from(RESOLVER_SECRET).public_key().as_bytes();
    let cert = DnscryptCertificate::sign(
        &PROVIDER_SECRET,
        public,
        *b"DONNALAB",
        1,
        now - 60,
        now + 86400,
    )?;
    let crypt = DnscryptServerConfig::new(
        DomainName::from_dotted("2.dnscrypt-cert.example.test.")?,
        vec![DnscryptResolverIdentity::new(cert, RESOLVER_SECRET)?],
    )?;
    println!(
        "Donna laboratory: UDP/TCP 5300, TLS 8530, HTTPS 8443, QUIC 8853, DNSCrypt UDP/TCP 5443"
    );
    tokio::try_join!(
        UdpTransport.serve(format!("{host}:5300").parse()?, server.clone()),
        TcpTransport.serve(format!("{host}:5300").parse()?, server.clone()),
        tls.serve(format!("{host}:8530").parse()?, server.clone()),
        doh.serve(format!("{host}:8443").parse()?, server.clone()),
        doq.serve(format!("{host}:8853").parse()?, server.clone()),
        DnscryptTransportServer::new(crypt.clone())
            .serve(format!("{host}:5443").parse()?, server.clone()),
        DnscryptUdpTransportServer::new(crypt).serve(format!("{host}:5443").parse()?, server)
    )?;
    Ok(())
}

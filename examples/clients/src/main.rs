use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use dns::{DomainName, RCode};
mod fixtures;
use fixtures::{PROVIDER_SECRET, query, roots};
type Failure = Box<dyn std::error::Error + Send + Sync>;
use transport::{
    DnscryptClientConfig, DnscryptTransport, DnscryptUdpTransport, DohClientConfig, DohMethod,
    DohTransport, DoqClientConfig, DoqTransport, TcpTransport, TlsClientConfig, TlsTransport,
    Transport, UdpTransport,
};

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let args: Vec<_> = env::args().collect();
    let protocol = args.get(1).map(String::as_str).unwrap_or("udp");
    let address: SocketAddr = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("127.0.0.1:53")
        .parse()?;
    let directory = PathBuf::from(env::var("CERT_DIR").unwrap_or("/certs".into()));
    let crypt = || {
        DnscryptClientConfig::new(
            DomainName::from_dotted("example.test.").unwrap(),
            ed25519_dalek::SigningKey::from_bytes(&PROVIDER_SECRET)
                .verifying_key()
                .to_bytes(),
        )
    };
    let transport: Box<dyn Transport> = match protocol {
        "udp" => Box::new(UdpTransport),
        "tcp" => Box::new(TcpTransport),
        "tls" => Box::new(TlsTransport::new(TlsClientConfig::new(
            roots(&directory)?,
            "localhost".into(),
        )?)),
        "doh-get" | "doh-post" => Box::new(DohTransport::new(DohClientConfig::new(
            roots(&directory)?,
            "localhost".into(),
            format!("localhost:{}", address.port()),
            "/dns-query".into(),
            if protocol == "doh-get" {
                DohMethod::Get
            } else {
                DohMethod::Post
            },
        )?)),
        "doq" => Box::new(DoqTransport::new(DoqClientConfig::new(
            roots(&directory)?,
            "localhost".into(),
        )?)),
        "dnscrypt-udp" => Box::new(DnscryptUdpTransport::new(crypt()?)?),
        "dnscrypt-tcp" => Box::new(DnscryptTransport::new(crypt()?)?),
        _ => return Err(format!("unknown protocol: {protocol}").into()),
    };
    let answer = transport
        .exchange(
            address,
            &query("www.example.test.")?,
            Duration::from_secs(5),
        )
        .await?;
    assert_eq!(answer.headers.rcode, RCode::Ok);
    assert!(answer.answers.iter().any(|record| matches!(record.rdata,
        dns::RData::A(address) if address.octets() == [192, 0, 2, 80])));
    println!(
        "PASS Donna {protocol} client against {address}: {:?}",
        answer.answers
    );
    Ok(())
}

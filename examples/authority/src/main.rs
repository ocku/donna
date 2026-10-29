//! Minimal authoritative server; no certificates or laboratory services required.
use std::{env, net::SocketAddr};

use dns::{DomainName, master::MasterFile};
use nameserver::{NameServer, NameServerConfig, Zone};
use transport::{TcpTransport, TransportServer, UdpTransport};

type Failure = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let address: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:5300".into())
        .parse()?;
    let path = env::var("ZONE_FILE")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/zone.db").into());
    let apex = DomainName::from_dotted("example.test.")?;
    let master = MasterFile::parse(&std::fs::read_to_string(path)?, Some(apex.clone()))?;
    let records = master.records.len();
    let server = NameServer::with_config(NameServerConfig::default());
    server.install(Zone::from_master(apex, master)?).await?;
    println!("Authority: {records} records; plain UDP/TCP {address}");
    tokio::try_join!(
        UdpTransport.serve(address, server.clone()),
        TcpTransport.serve(address, server)
    )?;
    Ok(())
}

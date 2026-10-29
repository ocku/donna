//! Plain UDP/TCP authority for matched service RAM observations.
use std::{env, net::SocketAddr};

use dns::{DomainName, master::MasterFile};
use donna_interop::Failure;
use nameserver::{NameServer, NameServerConfig, Zone};
use transport::{TcpTransport, TransportServer, UdpTransport};

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let address: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:53".into())
        .parse()?;
    let path = env::var("ZONE_FILE").unwrap_or_else(|_| "/work/zone.db".into());
    let apex = DomainName::from_dotted("example.test.")?;
    let master = MasterFile::parse(&std::fs::read_to_string(path)?, Some(apex.clone()))?;
    let records = master.records.len();
    let server = NameServer::with_config(NameServerConfig::default());
    server.install(Zone::from_master(apex, master)?).await?;
    println!("RAM fixture: {records} records; plain UDP/TCP {address}");
    tokio::try_join!(
        UdpTransport.serve(address, server.clone()),
        TcpTransport.serve(address, server)
    )?;
    Ok(())
}

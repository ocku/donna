use dns::{DomainName, RecordType, master::MasterFile};
use resolver::{RecursiveServer, Resolver, ResolverConfig};
use std::{env, time::Duration};
use transport::{TcpTransport, TransportServer, UdpTransport};

type Failure = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let host = env::var("LISTEN_HOST").unwrap_or("127.0.0.1".into());
    let root = env::var("ROOT_SERVER")?.parse()?;
    // The ordinary interoperability fixture stays non-validating. The signed
    // comparison supplies public DNSKEY anchors explicitly for both resolvers.
    let trust_anchors = if let Some(path) = env::var_os("TRUST_ANCHOR_FILE") {
        let anchors =
            MasterFile::parse(&std::fs::read_to_string(path)?, Some(DomainName::root()))?.records;
        if anchors.is_empty()
            || anchors
                .iter()
                .any(|record| record.rtype != RecordType::DNSKEY)
        {
            return Err("TRUST_ANCHOR_FILE must contain DNSKEY records only".into());
        }
        anchors
    } else {
        Vec::new()
    };
    // The recursive comparison also checks the explicit cache-disabled mode.
    let cache_capacity = match env::var("CACHE_CAPACITY") {
        Ok(value) => value.parse()?,
        Err(env::VarError::NotPresent) => ResolverConfig::default().cache_capacity,
        Err(error) => return Err(error.into()),
    };
    let server = RecursiveServer::with_resolver(Resolver::new(
        UdpTransport,
        ResolverConfig {
            root_servers: vec![root],
            trust_anchors,
            cache_capacity,
            timeout: Duration::from_secs(2),
            ..ResolverConfig::default()
        },
    ));
    tokio::try_join!(
        UdpTransport.serve(format!("{host}:5301").parse()?, server.clone()),
        TcpTransport.serve(format!("{host}:5301").parse()?, server)
    )?;
    Ok(())
}

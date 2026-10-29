//! RFC 3007 primary with a durable snapshot and an explicit TSIG grant.

mod sig0_fixture;
mod snapshot;

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use dns::{ClassType, DomainName, RecordType, TsigAlgorithm, TsigKey, master::MasterFile};
use nameserver::{
    NameServer, NameServerConfig, NotifyConfig, NotifyTarget, UpdateIdentity, UpdateRule, Zone,
};
use snapshot::Snapshot;
use transport::{TcpTransport, TransportServer, UdpTransport};

type Failure = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let address: SocketAddr = env::var("UPDATE_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:5301".into())
        .parse()?;
    let apex = DomainName::from_dotted("example.test.")?;
    let key_name = DomainName::from_dotted("interop-key.")?;
    let persistence = Arc::new(Snapshot(PathBuf::from(
        env::var("SNAPSHOT_FILE").unwrap_or_else(|_| "zone.wire".into()),
    )));
    let master = match persistence.load()? {
        Some(master) => master,
        None => MasterFile::parse(
            &std::fs::read_to_string(
                env::var("ZONE_FILE")
                    .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/zone.db").into()),
            )?,
            Some(apex.clone()),
        )?,
    };
    let notify = if let Ok(target) = env::var("NOTIFY_TARGET") {
        let target = tokio::net::lookup_host(target)
            .await?
            .next()
            .ok_or("NOTIFY_TARGET did not resolve")?;
        Some(
            NotifyConfig::new(
                UdpTransport,
                [NotifyTarget::new(apex.clone(), ClassType::IN, target)],
            )
            .with_retry_policy(Duration::from_secs(1), std::num::NonZeroU8::new(3).unwrap()),
        )
    } else {
        None
    };
    let server = NameServer::with_config(NameServerConfig {
        tsig_keys: vec![TsigKey::new(
            key_name.clone(),
            TsigAlgorithm::HmacSha256,
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )?],
        sig0_keys: vec![sig0_fixture::key()?],
        update_rules: vec![
            UpdateRule {
                identity: UpdateIdentity::Tsig(key_name),
                zone: apex.clone(),
                name: DomainName::from_dotted("dynamic.example.test.")?,
                record_types: vec![RecordType::A],
                include_subdomains: false,
            },
            UpdateRule {
                identity: UpdateIdentity::Sig0(DomainName::from_dotted("sig0-key.example.test.")?),
                zone: apex.clone(),
                name: DomainName::from_dotted("sig0-dynamic.example.test.")?,
                record_types: vec![RecordType::A],
                include_subdomains: false,
            },
        ],
        update_persistence: Some(persistence),
        notify,
        max_ixfr_history: 8,
        ..NameServerConfig::default()
    });
    server.install(Zone::from_master(apex, master)?).await?;
    println!("serving durable TSIG UPDATE over UDP/TCP on {address}");
    tokio::try_join!(
        UdpTransport.serve(address, server.clone()),
        TcpTransport.serve(address, server),
    )?;
    Ok(())
}

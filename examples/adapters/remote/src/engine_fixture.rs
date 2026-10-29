//! Real PostgreSQL catalog with a counting in-process authoritative transport.
use crate::{postgres_zones::PostgresZones, redis_engine::RedisCacheEngine};
use dns::{
    ClassType, DomainName, Message, QClassType, QueryType, Question, RecordType, master::MasterFile,
};
use nameserver::{NameServer, NameServerConfig, Zone, ZoneSnapshot, ZoneStore, ZoneStoreError};
use resolver::{CacheEngineConfig, Resolver, ResolverConfig};
use std::{
    env,
    error::Error,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use transport::{Transport, TransportError};

pub type Failure = Box<dyn Error + Send + Sync>;
#[derive(Clone)]
pub struct Authority {
    pub server: NameServer,
    roles: [NameServer; 3],
    pub exchanges: Arc<AtomicUsize>,
    pub captures: Arc<Mutex<Vec<UpstreamCapture>>>,
    origin: Instant,
    pub unavailable: Arc<AtomicBool>,
}
#[derive(Clone)]
pub struct UpstreamCapture {
    pub query: Message,
    pub response: Message,
    pub wall: u128,
    pub mono: u128,
}
impl Transport for Authority {
    fn exchange<'a>(
        &'a self,
        address: SocketAddr,
        request: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.exchanges.fetch_add(1, Ordering::Relaxed);
            if self.unavailable.load(Ordering::Relaxed) {
                return Err(std::io::Error::other("fixture authority unavailable").into());
            }
            let index = match address.ip().to_string().as_str() {
                "172.29.53.70" => 0,
                "172.29.53.71" => 1,
                "172.29.53.72" => 2,
                _ => return Err(std::io::Error::other("unknown fixture authority").into()),
            };
            let response = self.roles[index].handle(request.clone()).await;
            let capture = UpstreamCapture {
                query: request.clone(),
                response: response.clone(),
                wall: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(std::io::Error::other)?
                    .as_nanos(),
                mono: self.origin.elapsed().as_nanos(),
            };
            let mut captures = self
                .captures
                .lock()
                .map_err(|_| std::io::Error::other("fixture capture lock poisoned"))?;
            if captures.len() >= 4096 {
                return Err(std::io::Error::other("fixture capture bound exceeded").into());
            }
            captures.push(capture);
            Ok(response)
        })
    }
}
#[derive(Debug)]
struct RoleCatalog {
    inner: Arc<PostgresZones>,
    apex: DomainName,
}
impl ZoneStore for RoleCatalog {
    fn snapshot<'a>(&'a self) -> transport::BoxFuture<'a, Result<ZoneSnapshot, ZoneStoreError>> {
        Box::pin(async move {
            let snapshot = self.inner.snapshot().await?;
            ZoneSnapshot::new(
                snapshot.revision().to_vec(),
                snapshot.zones().filter(|z| z.apex() == &self.apex).cloned(),
            )
        })
    }
    fn compare_exchange<'a>(
        &'a self,
        _: &'a [u8],
        _: &'a [Arc<Zone>],
    ) -> transport::BoxFuture<'a, Result<bool, ZoneStoreError>> {
        Box::pin(async { Err("fixture role catalog is read-only".into()) })
    }
}
pub fn work(name: &str) -> PathBuf {
    PathBuf::from(env::var_os("FIXTURE_DIR").unwrap_or_else(|| "/work".into())).join(name)
}
pub fn zone(name: &str, origin: &str) -> Result<Zone, Failure> {
    let apex = DomainName::from_dotted(origin)?;
    Ok(Zone::from_master(
        apex.clone(),
        MasterFile::parse(&std::fs::read_to_string(work(name))?, Some(apex))?,
    )?)
}
pub async fn catalog(url: String, install: bool, origin: Instant) -> Result<Authority, Failure> {
    let store = Arc::new(PostgresZones::new(url));
    if install {
        store.initialize().await?;
    }
    let server = NameServer::with_zone_store(NameServerConfig::default(), store.clone());
    if install {
        for (file, origin) in [
            ("root.db", "."),
            ("tld.db", "test."),
            ("leaf.db", "example.test."),
        ] {
            server.install(zone(file, origin)?).await?;
        }
    }
    let roles = [".", "test.", "example.test."].map(|origin| {
        NameServer::with_zone_store(
            NameServerConfig::default(),
            Arc::new(RoleCatalog {
                inner: store.clone(),
                apex: DomainName::from_dotted(origin).unwrap(),
            }),
        )
    });
    Ok(Authority {
        server,
        roles,
        exchanges: Arc::new(AtomicUsize::new(0)),
        captures: Arc::new(Mutex::new(Vec::new())),
        origin,
        unavailable: Arc::new(AtomicBool::new(false)),
    })
}
pub fn config(capacity: usize) -> Result<ResolverConfig, Failure> {
    let anchors = MasterFile::parse(
        &std::fs::read_to_string(work("anchors.zone"))?,
        Some(DomainName::root()),
    )?
    .records;
    assert!(!anchors.is_empty() && anchors.iter().all(|r| r.rtype == RecordType::DNSKEY));
    Ok(ResolverConfig {
        root_servers: vec!["172.29.53.70:53".parse()?],
        trust_anchors: anchors,
        cache_capacity: capacity,
        failure_ttl: Duration::from_secs(30),
        timeout: Duration::from_secs(2),
        ..ResolverConfig::default()
    })
}
pub fn secret() -> Result<[u8; 32], Failure> {
    let bytes =
        std::fs::read(env::var_os("CACHE_SECRET_FILE").ok_or("CACHE_SECRET_FILE required")?)?;
    Ok(bytes
        .try_into()
        .map_err(|_| "cache secret must contain32bytes")?)
}
pub fn external(
    authority: Authority,
    engine: Arc<RedisCacheEngine>,
    scope: &[u8],
    capacity: usize,
) -> Result<Resolver<Authority>, Failure> {
    Ok(Resolver::with_cache_engine(
        authority,
        config(capacity)?,
        CacheEngineConfig::new(engine, scope, secret()?)?,
    ))
}
pub fn question(owner: &str, kind: QueryType) -> Result<Question, Failure> {
    Ok(Question {
        qname: DomainName::from_dotted(owner)?,
        qtype: kind,
        qclass: QClassType::Class(ClassType::IN),
    })
}
pub fn cases() -> Result<Vec<(&'static str, Question)>, Failure> {
    Ok(vec![
        ("a", question("coherence.example.test.", QueryType::A)?),
        (
            "aaaa",
            question("coherence.example.test.", QueryType::AAAA)?,
        ),
        ("txt", question("coherence.example.test.", QueryType::TXT)?),
        ("dname", question("prime.old.example.test.", QueryType::A)?),
        ("negative", question("gone.example.test.", QueryType::A)?),
        (
            "descendant",
            question("new.gone.example.test.", QueryType::AAAA)?,
        ),
    ])
}

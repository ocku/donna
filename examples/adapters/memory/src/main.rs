//! Application-owned adapters using only Donna's public extension points.

mod cache;

use cache::ApplicationCache;

use dns::{DomainName, FromWire, IntoWire, Message, RCode, ResourceRecord, master::MasterFile};
use nameserver::{NameServer, NameServerConfig, Zone, ZoneSnapshot, ZoneStore, ZoneStoreError};
use resolver::{
    CacheEngine, CacheEngineConfig, CacheMutationBatch, CacheReadPlan, CacheReadResult,
    ResolveError, Resolver, ResolverConfig,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use transport::{Transport, TransportError};

type Failure = Box<dyn std::error::Error + Send + Sync>;

fn query(name: &str) -> Result<Message, Failure> {
    Ok(Message::builder()
        .headers(dns::Headers {
            id: 1234,
            rd: true,
            ..dns::Headers::default()
        })
        .questions([dns::Question {
            qname: DomainName::from_dotted(name)?,
            qtype: dns::QueryType::A,
            qclass: dns::QClassType::Class(dns::ClassType::IN),
        }])
        .build()?)
}

// Store independent wire values, not Donna's in-memory indexes. A database
// adapter can store these bytes in its own schema and reconstruct indexes on
// load. Each record is a complete wire value, with no cross-record pointers.
#[derive(Clone, Debug)]
struct StoredZone {
    apex: Vec<u8>,
    records: Vec<Vec<u8>>,
}

impl StoredZone {
    fn encode(zone: &Zone) -> Result<Self, ZoneStoreError> {
        Ok(Self {
            apex: zone.apex().into_wire()?,
            records: zone
                .records()
                .iter()
                .map(IntoWire::into_wire)
                .collect::<Result<_, _>>()?,
        })
    }

    fn decode(&self) -> Result<Arc<Zone>, ZoneStoreError> {
        let apex = DomainName::from_wire(&self.apex)?;
        let records = self
            .records
            .iter()
            .map(|bytes| ResourceRecord::from_wire(bytes))
            .collect::<Result<_, _>>()?;
        Ok(Arc::new(Zone::from_master(apex, MasterFile { records })?))
    }
}

#[derive(Debug, Default)]
struct ApplicationZones {
    catalog: Mutex<(u64, Vec<StoredZone>)>,
    unavailable: AtomicBool,
}

impl ZoneStore for ApplicationZones {
    fn snapshot<'future>(
        &'future self,
    ) -> transport::BoxFuture<'future, Result<ZoneSnapshot, ZoneStoreError>> {
        Box::pin(async move {
            if self.unavailable.load(Ordering::Relaxed) {
                return Err("application catalog unavailable".into());
            }
            let (revision, stored) = self
                .catalog
                .lock()
                .map_err(|_| "catalog lock poisoned")?
                .clone();
            let zones = stored
                .iter()
                .map(StoredZone::decode)
                .collect::<Result<Vec<_>, _>>()?;
            ZoneSnapshot::new(revision.to_be_bytes().to_vec(), zones)
        })
    }

    fn compare_exchange<'future>(
        &'future self,
        expected: &'future [u8],
        zones: &'future [Arc<Zone>],
    ) -> transport::BoxFuture<'future, Result<bool, ZoneStoreError>> {
        Box::pin(async move {
            if self.unavailable.load(Ordering::Relaxed) {
                return Err("application catalog unavailable".into());
            }
            let mut catalog = self.catalog.lock().map_err(|_| "catalog lock poisoned")?;
            if catalog.0.to_be_bytes() != expected {
                return Ok(false);
            }
            // Reject duplicate apex/class pairs before committing the catalog.
            ZoneSnapshot::new(Vec::new(), zones.iter().cloned())?;
            let revision = catalog.0.checked_add(1).ok_or("revision exhausted")?;
            let stored = zones
                .iter()
                .map(|zone| StoredZone::encode(zone))
                .collect::<Result<_, _>>()?;
            *catalog = (revision, stored);
            Ok(true)
        })
    }
}

#[derive(Clone)]
struct ApplicationTransport {
    authority: NameServer,
    exchanges: Arc<AtomicUsize>,
}

impl Transport for ApplicationTransport {
    fn exchange<'future>(
        &'future self,
        _: SocketAddr,
        request: &'future Message,
        _: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.exchanges.fetch_add(1, Ordering::Relaxed);
            Ok(self.authority.handle(request.clone()).await)
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let zones = Arc::new(ApplicationZones::default());
    let authority = NameServer::with_zone_store(NameServerConfig::default(), zones.clone());
    let apex = DomainName::from_dotted("example.test.")?;
    let master = MasterFile::parse(
        "@ 300 IN SOA ns.example.test. hostmaster.example.test. 1 60 60 3600 30\n@ 300 IN NS ns.example.test.\nns 300 IN A 192.0.2.53\nwww 300 IN A 192.0.2.80\nopaque 300 IN TYPE65000 \\# 4 00ff0102\n",
        Some(apex.clone()),
    )?;
    authority.install(Zone::from_master(apex, master)?).await?;
    // A stale writer must fail even when the intervening commit published the
    // same catalog. Revisions identify commits, not just catalog contents.
    let catalog = zones.snapshot().await?;
    let replacement: Vec<_> = catalog.zones().cloned().collect();
    let original_records = zones.catalog.lock().map_err(|_| "catalog lock poisoned")?.1[0]
        .records
        .clone();
    assert_eq!(
        StoredZone::encode(&replacement[0])?.records,
        original_records
    );
    assert!(
        zones
            .compare_exchange(catalog.revision(), &replacement)
            .await?
    );
    assert!(
        !zones
            .compare_exchange(catalog.revision(), &replacement)
            .await?
    );
    drop(authority);
    // Reconstructing the server obtains its catalog from the application store.
    let authority = NameServer::with_zone_store(NameServerConfig::default(), zones.clone());
    let request = query("www.example.test.")?;
    assert_eq!(authority.handle(request.clone()).await.answers.len(), 1);
    // A corrupt stored record cannot silently turn into a different zone.
    let original = {
        let mut catalog = zones.catalog.lock().map_err(|_| "catalog lock poisoned")?;
        let original = catalog.1.clone();
        catalog.1[0].records[0].clear();
        original
    };
    assert_eq!(
        authority.handle(request.clone()).await.headers.rcode,
        RCode::ServerFailure
    );
    zones.catalog.lock().map_err(|_| "catalog lock poisoned")?.1 = original;
    zones.unavailable.store(true, Ordering::Relaxed);
    assert_eq!(
        authority.handle(request.clone()).await.headers.rcode,
        RCode::ServerFailure
    );
    zones.unavailable.store(false, Ordering::Relaxed);

    let cache = Arc::new(ApplicationCache::default());
    // Even an empty write advances the revision, preventing stale writers
    // from committing against an identical intervening state.
    let namespace = b"adapter-contract-check";
    let plan = CacheReadPlan {
        reads: vec![],
        maximum_entries: 16,
        maximum_bytes: 1024,
    };
    let CacheReadResult::Read(initial) = cache.read(namespace, None, &plan).await? else {
        return Err("initial cache read conflicted".into());
    };
    let revision = cache
        .apply(namespace, &initial.revision, &CacheMutationBatch::default())
        .await?
        .ok_or("initial cache write conflicted")?;
    assert!(
        cache
            .apply(namespace, &revision, &CacheMutationBatch::default())
            .await?
            .is_some()
    );
    assert!(
        cache
            .apply(namespace, &revision, &CacheMutationBatch::default())
            .await?
            .is_none()
    );
    assert!(matches!(
        cache.read(namespace, Some(&revision), &plan).await?,
        CacheReadResult::Conflict
    ));
    let exchanges = Arc::new(AtomicUsize::new(0));
    let transport = ApplicationTransport {
        authority,
        exchanges: exchanges.clone(),
    };
    let make = || -> Result<Resolver<ApplicationTransport>, Failure> {
        Ok(Resolver::with_cache_engine(
            transport.clone(),
            ResolverConfig {
                root_servers: vec!["192.0.2.53:53".parse()?],
                ..ResolverConfig::default()
            },
            // Fixed only for this disposable example. Applications provide a
            // random secret kept outside their cache, stable across restarts.
            CacheEngineConfig::new(cache.clone(), b"application-example".to_vec(), [42; 32])?,
        ))
    };
    let question = request.questions[0].clone();
    let first = make()?;
    assert_eq!(first.resolve(question.clone()).await?.answers.len(), 1);
    assert_eq!(exchanges.load(Ordering::Relaxed), 1);
    drop(first);
    let restarted = make()?;
    assert_eq!(restarted.resolve(question.clone()).await?.answers.len(), 1);
    assert_eq!(exchanges.load(Ordering::Relaxed), 1);
    cache.unavailable.store(true, Ordering::Relaxed);
    assert!(matches!(
        restarted.resolve(question.clone()).await,
        Err(ResolveError::CacheBackend(_))
    ));
    cache.unavailable.store(false, Ordering::Relaxed);
    assert_eq!(restarted.resolve(question).await?.answers.len(), 1);
    assert_eq!(exchanges.load(Ordering::Relaxed), 1);
    println!(
        "PASS public adapters: reconstructed catalog, cache reuse, unavailable stores, recovery"
    );
    Ok(())
}

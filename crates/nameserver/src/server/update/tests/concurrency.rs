use std::{
    fmt,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use dns::master::MasterFile;
use dns::{
    ClassType, DomainName, Headers, Message, OpCode, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord,
};
use tokio::sync::Semaphore;

use crate::{NameServer, NameServerConfig, UpdatePersistence, UpdatePersistenceError, Zone};

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn record(owner: DomainName, rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype,
        class: ClassType::IN,
        ttl: 300,
        rdata,
    }
}

fn zone(serial: u32) -> Zone {
    let apex = name(&["example"]);
    Zone::from_master(
        apex.clone(),
        MasterFile {
            records: vec![
                record(
                    apex.clone(),
                    RecordType::SOA,
                    RData::SOA {
                        mname: name(&["primary", "invalid"]),
                        rname: DomainName::root(),
                        serial,
                        refresh: 60,
                        retry: 60,
                        expire: 3_600,
                        minimum: 300,
                    },
                ),
                record(apex, RecordType::NS, RData::NS(DomainName::root())),
            ],
        },
    )
    .unwrap()
}

fn update(owner: &str, address: Ipv4Addr) -> Message {
    Message::builder()
        .headers(Headers {
            opcode: OpCode::Update,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .authorities([record(
            name(&[owner, "example"]),
            RecordType::A,
            RData::A(address),
        )])
        .build()
        .unwrap()
}

fn query(owner: DomainName, qtype: QueryType) -> Message {
    Message::builder()
        .questions([Question {
            qname: owner,
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

struct QueryingPersistence {
    server: Mutex<Option<NameServer>>,
    observed: Mutex<Vec<RCode>>,
}

impl fmt::Debug for QueryingPersistence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QueryingPersistence")
    }
}

impl UpdatePersistence for QueryingPersistence {
    fn persist<'future>(
        &'future self,
        _zone: &'future Zone,
    ) -> transport::BoxFuture<'future, Result<(), UpdatePersistenceError>> {
        Box::pin(async move {
            let server = self.server.lock().unwrap().clone().unwrap();
            let response = server
                .handle(query(name(&["example"]), QueryType::SOA))
                .await;
            self.observed.lock().unwrap().push(response.headers.rcode);
            Ok(())
        })
    }
}

#[tokio::test]
async fn persistence_can_query_while_an_update_is_in_flight() {
    let persistence = Arc::new(QueryingPersistence {
        server: Mutex::new(None),
        observed: Mutex::new(Vec::new()),
    });
    let server = NameServer::with_config(NameServerConfig {
        update_persistence: Some(persistence.clone()),
        allow_insecure_updates: true,
        ..NameServerConfig::default()
    });
    *persistence.server.lock().unwrap() = Some(server.clone());
    server.install(zone(1)).await.unwrap();

    let response = tokio::time::timeout(
        Duration::from_secs(1),
        server.handle(update("one", Ipv4Addr::new(192, 0, 2, 1))),
    )
    .await
    .expect("persistence must not deadlock on the global zone-index lock");

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert_eq!(*persistence.observed.lock().unwrap(), vec![RCode::Ok]);
}

#[derive(Debug)]
struct BlockingPersistence {
    calls: AtomicUsize,
    started: Semaphore,
    release_first: Semaphore,
    snapshots: Mutex<Vec<Vec<ResourceRecord>>>,
}

impl BlockingPersistence {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            started: Semaphore::new(0),
            release_first: Semaphore::new(0),
            snapshots: Mutex::new(Vec::new()),
        }
    }
}

impl UpdatePersistence for BlockingPersistence {
    fn persist<'future>(
        &'future self,
        zone: &'future Zone,
    ) -> transport::BoxFuture<'future, Result<(), UpdatePersistenceError>> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.add_permits(1);
            if call == 0 {
                self.release_first.acquire().await.unwrap().forget();
            }
            self.snapshots.lock().unwrap().push(zone.records().to_vec());
            Ok(())
        })
    }
}

fn blocking_server(persistence: &Arc<BlockingPersistence>) -> NameServer {
    NameServer::with_config(NameServerConfig {
        update_persistence: Some(persistence.clone()),
        allow_insecure_updates: true,
        max_ixfr_history: 4,
        ..NameServerConfig::default()
    })
}

#[tokio::test]
async fn same_zone_updates_are_persisted_and_published_in_order_without_lost_data() {
    let persistence = Arc::new(BlockingPersistence::new());
    let server = blocking_server(&persistence);
    server.install(zone(1)).await.unwrap();

    let first_server = server.clone();
    let first = tokio::spawn(async move {
        first_server
            .handle(update("one", Ipv4Addr::new(192, 0, 2, 1)))
            .await
    });
    persistence.started.acquire().await.unwrap().forget();

    let second_server = server.clone();
    let second = tokio::spawn(async move {
        second_server
            .handle(update("two", Ipv4Addr::new(192, 0, 2, 2)))
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), persistence.started.acquire())
            .await
            .is_err(),
        "a later same-zone update must not overtake persistence"
    );

    persistence.release_first.add_permits(1);
    assert_eq!(first.await.unwrap().headers.rcode, RCode::Ok);
    assert_eq!(second.await.unwrap().headers.rcode, RCode::Ok);

    let snapshots = persistence.snapshots.lock().unwrap();
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots[0]
            .iter()
            .any(|record| record.name.eq_dns(&name(&["one", "example"])))
    );
    assert!(
        snapshots[1]
            .iter()
            .any(|record| record.name.eq_dns(&name(&["one", "example"])))
    );
    assert!(
        snapshots[1]
            .iter()
            .any(|record| record.name.eq_dns(&name(&["two", "example"])))
    );
    assert!(
        snapshots[1]
            .iter()
            .any(|record| matches!(record.rdata, RData::SOA { serial: 3, .. }))
    );
}

#[tokio::test]
async fn install_waits_for_an_earlier_same_zone_dynamic_commit() {
    let persistence = Arc::new(BlockingPersistence::new());
    let server = blocking_server(&persistence);
    server.install(zone(1)).await.unwrap();

    let update_server = server.clone();
    let pending_update = tokio::spawn(async move {
        update_server
            .handle(update("one", Ipv4Addr::new(192, 0, 2, 1)))
            .await
    });
    persistence.started.acquire().await.unwrap().forget();

    let install_server = server.clone();
    let mut pending_install =
        tokio::spawn(async move { install_server.install(zone(10)).await.unwrap() });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut pending_install)
            .await
            .is_err(),
        "install must participate in same-zone mutation ordering"
    );

    persistence.release_first.add_permits(1);
    assert_eq!(pending_update.await.unwrap().headers.rcode, RCode::Ok);
    pending_install.await.unwrap();

    let response = server
        .handle(query(name(&["example"]), QueryType::SOA))
        .await;
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::SOA { serial: 10, .. },
            ..
        }]
    ));
}

#[tokio::test]
async fn aborting_after_persistence_starts_does_not_split_the_commit() {
    let persistence = Arc::new(BlockingPersistence::new());
    let server = blocking_server(&persistence);
    server.install(zone(1)).await.unwrap();

    let updating = server.clone();
    let caller = tokio::spawn(async move {
        updating
            .handle(update("owned", Ipv4Addr::new(192, 0, 2, 44)))
            .await
    });
    persistence.started.acquire().await.unwrap().forget();

    // Force the owned commit to pause specifically between successful durable
    // persistence and in-memory publication, then cancel only its waiter.
    let zones = server.zones.write().await;
    persistence.release_first.add_permits(1);
    tokio::task::yield_now().await;
    caller.abort();
    drop(zones);

    let owner = name(&["owned", "example"]);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if server
                .handle(query(owner.clone(), QueryType::A))
                .await
                .answers
                .len()
                == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the server-owned commit must publish after its waiter is aborted");

    assert_eq!(persistence.snapshots.lock().unwrap().len(), 1);
    let histories = server.ixfr_history.lock().await;
    let key = (
        crate::name::dns_name_key(&name(&["example"])),
        ClassType::IN.value(),
    );
    assert_eq!(histories.get(&key).map(|history| history.len()), Some(1));
}

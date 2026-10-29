use super::*;
use crate::{InstallOutcome, NameServer, NameServerConfig};
use dns::{
    ClassType, DomainName, Headers, Message, OpCode, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord, master::MasterFile,
};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug)]
struct Store {
    catalog: Mutex<ZoneSnapshot>,
    fail_reads: AtomicBool,
    fail_commits: AtomicBool,
    conflict: AtomicBool,
    pause_commit: AtomicBool,
    commit_started: tokio::sync::Notify,
    commit_release: tokio::sync::Notify,
}
impl Store {
    fn new() -> Self {
        Self {
            catalog: Mutex::new(ZoneSnapshot::new(0_u64.to_be_bytes().to_vec(), []).unwrap()),
            fail_reads: AtomicBool::new(false),
            fail_commits: AtomicBool::new(false),
            conflict: AtomicBool::new(false),
            pause_commit: AtomicBool::new(false),
            commit_started: tokio::sync::Notify::new(),
            commit_release: tokio::sync::Notify::new(),
        }
    }
}

impl ZoneStore for Store {
    fn snapshot<'future>(
        &'future self,
    ) -> transport::BoxFuture<'future, Result<ZoneSnapshot, ZoneStoreError>> {
        Box::pin(async move {
            if self.fail_reads.load(Ordering::Relaxed) {
                return Err("storage unavailable".into());
            }
            Ok(self.catalog.lock().unwrap().clone())
        })
    }
    fn compare_exchange<'future>(
        &'future self,
        revision: &'future [u8],
        zones: &'future [Arc<Zone>],
    ) -> transport::BoxFuture<'future, Result<bool, ZoneStoreError>> {
        Box::pin(async move {
            if self.fail_commits.load(Ordering::Relaxed) {
                return Err("commit unavailable".into());
            }
            if self.pause_commit.swap(false, Ordering::Relaxed) {
                self.commit_started.notify_one();
                self.commit_release.notified().await;
            }
            let mut catalog = self.catalog.lock().unwrap();
            if self.conflict.swap(false, Ordering::Relaxed) || catalog.revision() != revision {
                return Ok(false);
            }
            let next = u64::from_be_bytes(revision.try_into().unwrap()) + 1;
            *catalog = ZoneSnapshot::new(next.to_be_bytes().to_vec(), zones.iter().cloned())?;
            Ok(true)
        })
    }
}
fn name(s: &str) -> DomainName {
    DomainName::from_dotted(s).unwrap()
}
fn zone(apex: &str, serial: u32, address: &str) -> Zone {
    let apex = name(apex);
    let text = format!(
        "@ 300 IN SOA ns.invalid. hostmaster.invalid. {serial} 60 60 3600 30\n@ 300 IN NS ns.invalid.\nwww 300 IN A {address}\n"
    );
    Zone::from_master(apex.clone(), MasterFile::parse(&text, Some(apex)).unwrap()).unwrap()
}
fn query(owner: &str, kind: QueryType) -> Message {
    Message::builder()
        .questions([Question {
            qname: name(owner),
            qtype: kind,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}
fn update() -> Message {
    Message::builder()
        .headers(Headers {
            opcode: OpCode::Update,
            ..Headers::default()
        })
        .questions([Question {
            qname: name("example."),
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .authorities([ResourceRecord {
            name: name("new.example."),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A("192.0.2.9".parse().unwrap()),
        }])
        .build()
        .unwrap()
}
#[tokio::test]
async fn shared_external_catalog_handles_conflicts_and_remote_replacement() {
    let store = Arc::new(Store::new());
    store.conflict.store(true, Ordering::Relaxed);
    let first = NameServer::with_zone_store(NameServerConfig::default(), store.clone());
    let second = NameServer::with_zone_store(NameServerConfig::default(), store.clone());
    let (a, b) = tokio::join!(
        first.install(zone("example.", 1, "192.0.2.1")),
        second.install(zone("other.", 1, "192.0.2.2"))
    );
    assert_eq!(a.unwrap(), InstallOutcome::Installed);
    assert_eq!(b.unwrap(), InstallOutcome::Installed);
    assert_eq!(store.snapshot().await.unwrap().zones().count(), 2);
    assert_eq!(
        first
            .handle(query("www.other.", QueryType::A))
            .await
            .answers
            .len(),
        1
    );
    assert_eq!(
        second
            .install(zone("example.", 2, "192.0.2.3"))
            .await
            .unwrap(),
        InstallOutcome::Replaced
    );
    let reply = first.handle(query("www.example.", QueryType::A)).await;
    assert!(matches!(reply.answers[0].rdata, RData::A(ip) if ip.to_string() == "192.0.2.3"));
    assert_eq!(
        first
            .install(zone("example.", 1, "192.0.2.1"))
            .await
            .unwrap(),
        InstallOutcome::StaleSerial
    );
    store.fail_reads.store(true, Ordering::Relaxed);
    assert_eq!(
        first
            .handle(query("www.example.", QueryType::A))
            .await
            .headers
            .rcode,
        RCode::ServerFailure
    );
    assert!(
        first
            .install(zone("example.", 3, "192.0.2.4"))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn external_updates_commit_without_builtin_persistence_and_fail_closed_on_conflict() {
    let store = Arc::new(Store::new());
    let server = NameServer::with_zone_store(
        NameServerConfig {
            allow_insecure_updates: true,
            ..NameServerConfig::default()
        },
        store.clone(),
    );
    server
        .install(zone("example.", 1, "192.0.2.1"))
        .await
        .unwrap();
    store.conflict.store(true, Ordering::Relaxed);
    let revision = store.snapshot().await.unwrap().revision().to_vec();
    assert_eq!(
        server.handle(update()).await.headers.rcode,
        RCode::ServerFailure
    );
    assert_eq!(store.snapshot().await.unwrap().revision(), revision);
    assert_eq!(
        server
            .handle(query("new.example.", QueryType::A))
            .await
            .headers
            .rcode,
        RCode::NameError
    );
    assert_eq!(server.handle(update()).await.headers.rcode, RCode::Ok);
    assert_eq!(
        server
            .handle(query("new.example.", QueryType::A))
            .await
            .answers
            .len(),
        1
    );
    let restored = NameServer::with_zone_store(NameServerConfig::default(), store.clone());
    assert_eq!(
        restored
            .handle(query("new.example.", QueryType::A))
            .await
            .answers
            .len(),
        1
    );
}
#[tokio::test]
async fn disconnected_update_keeps_its_external_commit_owned_by_server() {
    let store = Arc::new(Store::new());
    let server = NameServer::with_zone_store(
        NameServerConfig {
            allow_insecure_updates: true,
            ..NameServerConfig::default()
        },
        store.clone(),
    );
    server
        .install(zone("example.", 1, "192.0.2.1"))
        .await
        .unwrap();
    store.pause_commit.store(true, Ordering::Relaxed);
    let request_server = server.clone();
    let request = tokio::spawn(async move { request_server.handle(update()).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        store.commit_started.notified(),
    )
    .await
    .unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    store.commit_release.notify_one();
    let restored = NameServer::with_zone_store(NameServerConfig::default(), store);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if restored
                .handle(query("new.example.", QueryType::A))
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
    .unwrap();
}

#[tokio::test]
async fn external_transfer_and_cname_use_current_catalog() {
    let store = Arc::new(Store::new());
    let mut config = NameServerConfig::default();
    config.allow_axfr_to.push((
        "127.0.0.1".parse().unwrap(),
        "255.255.255.255".parse().unwrap(),
    ));
    let server = NameServer::with_zone_store(config, store.clone());
    let apex = name("example.");
    let master = MasterFile::parse("@ 300 IN SOA ns.invalid. hostmaster.invalid. 1 60 60 3600 30\n@ 300 IN NS ns.invalid.\nalias 300 IN CNAME www.other.\n", Some(apex.clone())).unwrap();
    server
        .install(Zone::from_master(apex, master).unwrap())
        .await
        .unwrap();
    server
        .install(zone("other.", 1, "192.0.2.8"))
        .await
        .unwrap();
    let reply = server.handle(query("alias.example.", QueryType::A)).await;
    assert_eq!(reply.answers.len(), 2);
    assert!(matches!(reply.answers[1].rdata, RData::A(ip) if ip.to_string() == "192.0.2.8"));
    let transfer = server
        .handle_transfer(
            "127.0.0.1:1024".parse().unwrap(),
            query("other.", QueryType::AXFR),
        )
        .await;
    assert!(
        transfer
            .iter()
            .flat_map(|m| &m.answers)
            .any(|rr| matches!(rr.rdata, RData::A(ip) if ip.to_string()=="192.0.2.8"))
    );
    store.fail_reads.store(true, Ordering::Relaxed);
    let failed = server
        .handle_transfer(
            "127.0.0.1:1024".parse().unwrap(),
            query("other.", QueryType::AXFR),
        )
        .await;
    assert_eq!(failed[0].headers.rcode, RCode::ServerFailure);
}

#[tokio::test]
async fn failed_external_commits_preserve_catalog_until_recovery() {
    let store = Arc::new(Store::new());
    let server = NameServer::with_zone_store(
        NameServerConfig {
            allow_insecure_updates: true,
            ..NameServerConfig::default()
        },
        store.clone(),
    );
    server
        .install(zone("example.", 1, "192.0.2.1"))
        .await
        .unwrap();
    let before = store.snapshot().await.unwrap().revision().to_vec();
    store.fail_commits.store(true, Ordering::Relaxed);
    assert!(
        server
            .install(zone("example.", 2, "192.0.2.2"))
            .await
            .is_err()
    );
    assert_eq!(
        server.handle(update()).await.headers.rcode,
        RCode::ServerFailure
    );
    assert_eq!(store.snapshot().await.unwrap().revision(), before);
    let reply = server.handle(query("www.example.", QueryType::A)).await;
    assert!(matches!(reply.answers[0].rdata, RData::A(ip) if ip.to_string() == "192.0.2.1"));
    assert_eq!(
        server
            .handle(query("new.example.", QueryType::A))
            .await
            .headers
            .rcode,
        RCode::NameError
    );
    store.fail_commits.store(false, Ordering::Relaxed);
    assert_eq!(server.handle(update()).await.headers.rcode, RCode::Ok);
    let restored = NameServer::with_zone_store(NameServerConfig::default(), store);
    assert_eq!(
        restored
            .handle(query("new.example.", QueryType::A))
            .await
            .answers
            .len(),
        1
    );
}

#[test]
fn snapshot_rejects_duplicate_dns_apex_and_class() {
    assert!(
        ZoneSnapshot::new(
            vec![],
            [
                Arc::new(zone("example.", 1, "192.0.2.1")),
                Arc::new(zone("EXAMPLE.", 2, "192.0.2.2"))
            ]
        )
        .is_err()
    );
}

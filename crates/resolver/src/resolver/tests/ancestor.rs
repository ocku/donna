use super::{AlgorithmSignals, Resolver};
use crate::{ResolveError, ResolverConfig, protocol::Referral};
use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use transport::{Transport, TransportError, TransportProtocol};

fn name(s: &str) -> DomainName {
    DomainName::from_dotted(s).unwrap()
}
fn addr(n: u8) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(192, 0, 2, n), 53))
}
fn question(s: &str) -> Question {
    Question {
        qname: name(s),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}
fn rr(owner: &str, kind: RecordType, data: RData) -> ResourceRecord {
    ResourceRecord {
        name: name(owner),
        rtype: kind,
        class: ClassType::IN,
        ttl: 300,
        rdata: data,
    }
}
fn soa(owner: &str) -> ResourceRecord {
    rr(
        owner,
        RecordType::SOA,
        RData::SOA {
            mname: name("ns.test."),
            rname: name("hostmaster.test."),
            serial: 1,
            refresh: 60,
            retry: 60,
            expire: 60,
            minimum: 30,
        },
    )
}
#[derive(Clone)]
pub(in crate::resolver) struct Hierarchy {
    failed: Arc<AtomicBool>,
    replacement: Arc<AtomicBool>,
    outside: Arc<AtomicBool>,
    counts: Arc<Mutex<HashMap<SocketAddr, usize>>>,
}
impl Hierarchy {
    pub(in crate::resolver) fn new() -> Self {
        Self {
            failed: Arc::new(AtomicBool::new(false)),
            replacement: Arc::new(AtomicBool::new(false)),
            outside: Arc::new(AtomicBool::new(false)),
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub(in crate::resolver) fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
    }
    pub(in crate::resolver) fn snapshot(&self) -> HashMap<SocketAddr, usize> {
        self.counts.lock().unwrap().clone()
    }
}
impl Transport for Hierarchy {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            *self.counts.lock().unwrap().entry(server).or_default() += 1;
            let q = &query.questions[0];
            let mut reply = Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: vec![],
                authorities: vec![],
                additionals: vec![],
            };
            if server == addr(3) && self.failed.load(Ordering::SeqCst) {
                reply.headers.rcode = dns::RCode::Refused;
            } else if server == addr(3)
                || server == addr(4)
                || (server == addr(2) && q.qname.is_descendant_of(&name("healthy.test.")))
            {
                reply.headers.aa = true;
                if q.qtype == QueryType::A {
                    reply.answers.push(ResourceRecord {
                        name: q.qname.clone(),
                        rtype: RecordType::A,
                        class: ClassType::IN,
                        ttl: 300,
                        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 80)),
                    });
                } else {
                    reply.authorities.push(soa("example.test."));
                }
            } else if server == addr(2) && q.qname.eq_dns(&name("good-ns.test.")) {
                reply.headers.aa = true;
                if q.qtype == QueryType::A {
                    reply.answers.push(rr(
                        "good-ns.test.",
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 4)),
                    ));
                } else {
                    reply.authorities.push(soa("test."));
                }
            } else if server == addr(2)
                && q.qname.eq_dns(&name("example.test."))
                && q.qtype == QueryType::DS
            {
                reply.headers.aa = true;
                reply.authorities.push(soa("test."));
            } else {
                let (zone, ns, target) = if server == addr(1) {
                    ("test.", "ns.test.", 2)
                } else {
                    (
                        "example.test.",
                        "ns.example.test.",
                        if self.replacement.load(Ordering::SeqCst) {
                            4
                        } else {
                            3
                        },
                    )
                };
                reply
                    .authorities
                    .push(rr(zone, RecordType::NS, RData::NS(name(ns))));
                reply.additionals.push(rr(
                    ns,
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, target)),
                ));
                if server == addr(2) && self.outside.load(Ordering::SeqCst) {
                    reply.authorities.push(rr(
                        zone,
                        RecordType::NS,
                        RData::NS(name("good-ns.test.")),
                    ));
                }
            }
            Ok(reply)
        })
    }
}
fn resolver(fixture: &Hierarchy, max_ttl: Duration) -> Resolver<Hierarchy> {
    Resolver::new(
        fixture.clone(),
        ResolverConfig {
            root_servers: vec![addr(1)],
            max_ttl,
            ..ResolverConfig::default()
        },
    )
}
async fn failed(resolver: &Resolver<Hierarchy>, owner: &str) {
    let result = resolver.resolve(question(owner)).await;
    assert!(
        matches!(
            result,
            Err(ResolveError::NoReachableServer | ResolveError::TemporaryServerFailure)
        ),
        "{result:?}"
    );
}
fn ancestors_unchanged(before: &HashMap<SocketAddr, usize>, after: &HashMap<SocketAddr, usize>) {
    for server in [addr(1), addr(2)] {
        assert_eq!(before.get(&server), after.get(&server), "{server}");
    }
}

#[tokio::test]
async fn failed_zone_fresh_names_suppress_ancestors_without_poisoning_positive_or_parent_ds() {
    let fixture = Hierarchy::new();
    let resolver = resolver(&fixture, Duration::from_secs(300));
    resolver
        .resolve(question("cached.example.test."))
        .await
        .unwrap();
    resolver
        .resolve(question("ok.healthy.test."))
        .await
        .unwrap();
    fixture.failed.store(true, Ordering::SeqCst);
    failed(&resolver, "cold.example.test.").await;
    let before = fixture.snapshot();
    for owner in [
        "new1.example.test.",
        "new2.example.test.",
        "new3.example.test.",
    ] {
        failed(&resolver, owner).await;
    }
    ancestors_unchanged(&before, &fixture.snapshot());
    let before = fixture.snapshot();
    resolver
        .resolve(question("cached.example.test."))
        .await
        .unwrap();
    resolver
        .resolve(question("ok.healthy.test."))
        .await
        .unwrap();
    assert_eq!(before, fixture.snapshot());
    let mut ds = question("example.test.");
    ds.qtype = QueryType::DS;
    let answer = resolver.resolve(ds).await.unwrap();
    assert!(answer.answers.is_empty());
    assert!(
        answer
            .authorities
            .iter()
            .any(|r| r.rtype == RecordType::SOA && r.name.eq_dns(&name("test.")))
    );
    // CD owns an independent recovery window; after its initial attempt, fresh CD names are suppressed too.
    let result = resolver
        .resolve_with_algorithm_signals(
            question("cd-cold.example.test."),
            AlgorithmSignals::default(),
            true,
        )
        .await;
    assert!(result.is_err());
    let before = fixture.snapshot();
    assert!(
        resolver
            .resolve_with_algorithm_signals(
                question("cd-next.example.test."),
                AlgorithmSignals::default(),
                true
            )
            .await
            .is_err()
    );
    ancestors_unchanged(&before, &fixture.snapshot());
    // Child queries still run while routing metadata is fresh, so actual recovery works immediately.
    fixture.failed.store(false, Ordering::SeqCst);
    resolver
        .resolve(question("recovered.example.test."))
        .await
        .unwrap();
}

#[tokio::test]
async fn expired_window_allows_bounded_stale_nameserver_recovery() {
    let fixture = Hierarchy::new();
    let resolver = resolver(&fixture, Duration::from_secs(300));
    resolver
        .resolve(question("cached.example.test."))
        .await
        .unwrap();
    fixture.failed.store(true, Ordering::SeqCst);
    failed(&resolver, "cold.example.test.").await;
    fixture.replacement.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    let before = fixture.snapshot();
    let answer = resolver
        .resolve(question("new-address.example.test."))
        .await
        .unwrap();
    assert!(!answer.answers.is_empty());
    assert!(fixture.snapshot().get(&addr(2)) > before.get(&addr(2)));
    assert!(fixture.snapshot().contains_key(&addr(4)));
}

#[tokio::test]
async fn lease_does_not_prevent_pending_alternative_nameserver_address_work() {
    let fixture = Hierarchy::new();
    let resolver = resolver(&fixture, Duration::from_secs(300));
    resolver
        .resolve(question("cached.example.test."))
        .await
        .unwrap();
    fixture.failed.store(true, Ordering::SeqCst);
    fixture.outside.store(true, Ordering::SeqCst);
    resolver.delegation_cache.insert(
        &Referral {
            zone: name("example.test."),
            class: ClassType::IN,
            candidates: vec![addr(3)],
            candidate_ttls: vec![(addr(3), Duration::from_secs(300))],
            trusted_glue: vec![],
            name_servers: vec![name("ns.example.test."), name("good-ns.test.")],
            ttl: Duration::from_secs(300),
        },
        Duration::from_secs(300),
    );
    let before = fixture.snapshot();
    assert!(
        resolver
            .resolve(question("alternative.example.test."))
            .await
            .is_ok()
    );
    let after = fixture.snapshot();
    assert_eq!(
        before.get(&addr(1)),
        after.get(&addr(1)),
        "no root requery for pending alternate"
    );
    assert!(after.get(&addr(3)) > before.get(&addr(3)) && after.contains_key(&addr(4)));
}

#[tokio::test]
async fn zero_ttl_delegations_retain_failure_tombstones_without_serving_expired_ns() {
    let fixture = Hierarchy::new();
    let resolver = resolver(&fixture, Duration::ZERO);
    fixture.failed.store(true, Ordering::SeqCst);
    failed(&resolver, "cold.example.test.").await;
    let before = fixture.snapshot();
    assert!(matches!(
        resolver.resolve(question("new.example.test.")).await,
        Err(ResolveError::CachedDelegationFailure)
    ));
    assert!(
        resolver
            .failure_cache
            .get(&question("new.example.test."), false)
            .is_none()
    );
    assert_eq!(
        before,
        fixture.snapshot(),
        "active tombstone must prevent a fresh ancestor bootstrap"
    );
    assert!(
        resolver
            .delegation_cache
            .get(&question("new.example.test."))
            .is_none()
    );
    fixture.failed.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    assert!(
        resolver
            .resolve(question("new.example.test."))
            .await
            .is_ok(),
        "reading cached failure must not extend its deadline or create a fresh terminal entry"
    );
}

#[tokio::test]
async fn busy_recovery_without_remote_attempts_is_not_a_cacheable_resolution_failure() {
    let fixture = Hierarchy::new();
    let resolver = resolver(&fixture, Duration::from_secs(300));
    resolver.delegation_cache.insert(
        &Referral {
            zone: name("example.test."),
            class: ClassType::IN,
            candidates: vec![],
            candidate_ttls: vec![],
            trusted_glue: vec![],
            name_servers: vec![name("ns.example.test.")],
            ttl: Duration::from_secs(300),
        },
        Duration::from_secs(300),
    );
    resolver.delegation_cache.claim_refresh(
        &name("example.test."),
        ClassType::IN,
        false,
        Duration::from_secs(1),
    );
    let q = question("fresh.example.test.");
    assert!(matches!(
        resolver.resolve(q.clone()).await,
        Err(ResolveError::DelegationRefreshInProgress)
    ));
    assert!(fixture.snapshot().is_empty());
    assert!(resolver.failure_cache.get(&q, false).is_none());
}

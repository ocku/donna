//! Exact NS-address failures reuse the ordinary bounded failure cache.
use super::{AlgorithmSignals, Resolver, ancestor::Hierarchy};
use crate::{ResolveError, ResolverConfig, cache::failure::FailureKind};
use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, atomic::AtomicUsize},
    time::Duration,
};
use transport::{Transport, TransportError, TransportProtocol};
fn name(s: &str) -> DomainName {
    DomainName::from_dotted(s).unwrap()
}
fn q(s: &str, kind: QueryType) -> Question {
    Question {
        qname: name(s),
        qtype: kind,
        qclass: QClassType::Class(ClassType::IN),
    }
}
fn addr(n: u8) -> SocketAddr {
    format!("192.0.2.{n}:53").parse().unwrap()
}
fn message(query: Question, answers: Vec<ResourceRecord>) -> Message {
    Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![query],
        answers,
        authorities: vec![],
        additionals: vec![],
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
#[derive(Clone)]
struct Addresses {
    requests: Arc<Mutex<Vec<Question>>>,
    success: Option<QueryType>,
}
impl Transport for Addresses {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            let question = query.questions[0].clone();
            self.requests.lock().unwrap().push(question.clone());
            let mut reply = message(question.clone(), vec![]);
            reply.headers.id = query.headers.id;
            if self.success == Some(question.qtype) {
                reply.answers.push(ResourceRecord {
                    name: question.qname,
                    rtype: if question.qtype == QueryType::A {
                        RecordType::A
                    } else {
                        RecordType::AAAA
                    },
                    class: ClassType::IN,
                    ttl: 300,
                    rdata: if question.qtype == QueryType::A {
                        RData::A(Ipv4Addr::new(192, 0, 2, 90))
                    } else {
                        RData::AAAA("2001:db8::90".parse().unwrap())
                    },
                });
            } else {
                reply.headers.rcode = dns::RCode::Refused;
                reply.headers.aa = false;
            }
            Ok(reply)
        })
    }
}
fn resolver(
    success: Option<QueryType>,
    validating: bool,
) -> (Resolver<Addresses>, Arc<Mutex<Vec<Question>>>) {
    let requests = Arc::new(Mutex::new(vec![]));
    let anchors = if validating {
        dns::master::MasterFile::parse(
            "test. 300 IN DNSKEY 257 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            Some(name("test.")),
        )
        .unwrap()
        .records
    } else {
        vec![]
    };
    (
        Resolver::new(
            Addresses {
                requests: requests.clone(),
                success,
            },
            ResolverConfig {
                root_servers: vec![addr(1)],
                trust_anchors: anchors,
                ..ResolverConfig::default()
            },
        ),
        requests,
    )
}
async fn lookup<'a, T: Transport>(
    resolver: &'a Resolver<T>,
    owner: &str,
    cd: bool,
) -> crate::resolver::address::NameServerAddressResolution<'a> {
    let signals = AlgorithmSignals {
        checking_disabled: cd,
        ..AlgorithmSignals::default()
    };
    resolver
        .resolve_name_server_addresses(
            &[name(owner)],
            &[],
            Arc::new(AtomicUsize::new(64)),
            None,
            Arc::new(signals),
        )
        .await
}
fn memo<T: Transport>(resolver: &Resolver<T>, question: &Question, cd: bool) {
    resolver
        .failure_cache
        .insert(question, cd, FailureKind::Server, Duration::from_secs(1));
}

#[tokio::test]
async fn fresh_client_names_reuse_ns_failures_but_each_original_failure_still_caches() {
    let authority = Hierarchy::new();
    let resolver = Resolver::new(
        authority.clone(),
        ResolverConfig {
            root_servers: vec![addr(1)],
            ..ResolverConfig::default()
        },
    );
    resolver
        .resolve(q("cached.example.test.", QueryType::A))
        .await
        .unwrap();
    authority.fail();
    assert!(
        resolver
            .resolve(q("cold.example.test.", QueryType::A))
            .await
            .is_err()
    );
    let before = authority.snapshot();
    for label in [
        "fresh1.example.test.",
        "fresh2.example.test.",
        "fresh3.example.test.",
    ] {
        let question = q(label, QueryType::A);
        assert!(matches!(
            resolver.resolve(question.clone()).await,
            Err(ResolveError::TemporaryServerFailure | ResolveError::NoReachableServer)
        ));
        assert!(
            resolver.failure_cache.get(&question, false).is_some(),
            "new observed remote failures remain admissible"
        );
        let warm = authority.snapshot();
        assert!(resolver.resolve(question).await.is_err());
        assert_eq!(warm, authority.snapshot());
    }
    let after = authority.snapshot();
    for server in [addr(1), addr(2)] {
        assert_eq!(before.get(&server), after.get(&server));
    }
    assert_eq!(
        after.get(&addr(3)).unwrap() - before.get(&addr(3)).unwrap(),
        3,
        "one actual leaf request per fresh client name"
    );
}

#[tokio::test]
async fn exact_class_cd_type_scope_and_alternate_family_remain_independent() {
    let (resolver, requests) = resolver(None, false);
    let first = lookup(&resolver, "ns.example.test.", false).await;
    assert!(first.addresses.is_empty() && first.error.is_none());
    assert_eq!(requests.lock().unwrap().len(), 2);
    let repeated = lookup(&resolver, "NS.EXAMPLE.TEST.", false).await;
    assert!(matches!(
        repeated.error,
        Some(ResolveError::CachedNameServerFailure)
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
    lookup(&resolver, "ns.example.test.", true).await;
    assert_eq!(requests.lock().unwrap().len(), 4);
    let (resolver, requests) = self::resolver(Some(QueryType::AAAA), false);
    memo(&resolver, &q("ns.example.test.", QueryType::A), false);
    let answer = lookup(&resolver, "ns.example.test.", false).await;
    assert!(answer.error.is_none());
    assert_eq!(answer.addresses, ["[2001:db8::90]:53".parse().unwrap()]);
    assert_eq!(requests.lock().unwrap()[0].qtype, QueryType::AAAA);
    let (resolver, requests) = self::resolver(Some(QueryType::A), false);
    let mut ch = q("ns.example.test.", QueryType::A);
    ch.qclass = QClassType::Class(ClassType::CH);
    memo(&resolver, &ch, false);
    assert_eq!(
        lookup(&resolver, "ns.example.test.", false).await.addresses,
        [addr(90)]
    );
    assert_eq!(
        requests.lock().unwrap()[0].qclass,
        QClassType::Class(ClassType::IN)
    );
}

#[tokio::test]
async fn complete_positive_address_wins_but_unvalidated_data_does_not_gain_provenance() {
    for validating in [false, true] {
        let (resolver, requests) = resolver(None, validating);
        let question = q("ns.example.test.", QueryType::A);
        resolver.cache_positive_entries(
            0,
            &message(
                question.clone(),
                vec![rr(
                    "ns.example.test.",
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 90)),
                )],
            ),
            &question,
        );
        memo(&resolver, &question, false);
        memo(&resolver, &q("ns.example.test.", QueryType::AAAA), false);
        let result = lookup(&resolver, "ns.example.test.", false).await;
        if validating {
            assert!(result.addresses.is_empty());
            assert!(matches!(
                result.error,
                Some(ResolveError::CachedNameServerFailure)
            ));
        } else {
            assert_eq!(result.addresses, [addr(90)]);
        }
        assert!(requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn cname_only_cache_must_honor_alias_and_terminal_failure_keys() {
    for terminal in [false, true] {
        let (resolver, requests) = resolver(None, false);
        let alias = q("alias.test.", QueryType::A);
        resolver.cache_positive_entries(
            0,
            &message(
                alias.clone(),
                vec![rr(
                    "alias.test.",
                    RecordType::CNAME,
                    RData::CNAME(name("target.test.")),
                )],
            ),
            &alias,
        );
        for kind in [QueryType::A, QueryType::AAAA] {
            memo(
                &resolver,
                &q(
                    if terminal {
                        "target.test."
                    } else {
                        "alias.test."
                    },
                    kind,
                ),
                false,
            );
        }
        let answer = lookup(&resolver, "alias.test.", false).await;
        assert!(
            answer.addresses.is_empty()
                && matches!(answer.error, Some(ResolveError::CachedNameServerFailure))
        );
        assert!(requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn complete_cached_alias_address_is_useful_data_before_failure_memo() {
    let (resolver, requests) = resolver(None, false);
    let alias = q("alias.test.", QueryType::A);
    resolver.cache_positive_entries(
        0,
        &message(
            alias.clone(),
            vec![
                rr(
                    "alias.test.",
                    RecordType::CNAME,
                    RData::CNAME(name("target.test.")),
                ),
                rr(
                    "target.test.",
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 90)),
                ),
            ],
        ),
        &alias,
    );
    memo(&resolver, &alias, false);
    memo(&resolver, &q("target.test.", QueryType::A), false);
    assert_eq!(
        lookup(&resolver, "alias.test.", false).await.addresses,
        [addr(90)]
    );
    assert!(requests.lock().unwrap().is_empty());
}

struct AliasOnly {
    requests: Arc<Mutex<Vec<Question>>>,
}
impl Transport for AliasOnly {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.requests
                .lock()
                .unwrap()
                .push(query.questions[0].clone());
            assert!(
                query.questions[0].qname.eq_dns(&name("alias.test.")),
                "cached target failure must stop target network query"
            );
            let mut reply = message(
                query.questions[0].clone(),
                vec![rr(
                    "alias.test.",
                    RecordType::CNAME,
                    RData::CNAME(name("target.test.")),
                )],
            );
            reply.headers.id = query.headers.id;
            Ok(reply)
        })
    }
}
#[tokio::test]
async fn validating_mode_network_cname_still_honors_target_failure_without_trusting_cached_data() {
    let requests = Arc::new(Mutex::new(vec![]));
    let anchors = dns::master::MasterFile::parse(
        "test. 300 IN DNSKEY 257 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        Some(name("test.")),
    )
    .unwrap()
    .records;
    let resolver = Resolver::new(
        AliasOnly {
            requests: requests.clone(),
        },
        ResolverConfig {
            root_servers: vec![addr(1)],
            trust_anchors: anchors,
            ..ResolverConfig::default()
        },
    );
    for kind in [QueryType::A, QueryType::AAAA] {
        memo(&resolver, &q("target.test.", kind), false);
    }
    let result = lookup(&resolver, "alias.test.", false).await;
    assert!(matches!(
        result.error,
        Some(ResolveError::CachedNameServerFailure)
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn useful_negative_address_data_also_precedes_failure_memo() {
    let (resolver, requests) = resolver(None, false);
    for kind in [QueryType::A, QueryType::AAAA] {
        let question = q("ns.example.test.", kind);
        let mut reply = message(question.clone(), vec![]);
        reply.authorities.push(rr(
            "example.test.",
            RecordType::SOA,
            RData::SOA {
                mname: name("ns.example.test."),
                rname: name("hostmaster.example.test."),
                serial: 1,
                refresh: 60,
                retry: 60,
                expire: 300,
                minimum: 30,
            },
        ));
        resolver.cache_response_entries(0, &reply, &question, &question, true);
        memo(&resolver, &question, false);
    }
    let answer = lookup(&resolver, "ns.example.test.", false).await;
    assert!(
        answer.addresses.is_empty() && answer.error.is_none(),
        "NODATA is useful DNS data, not a resolution failure"
    );
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn explicit_zero_capacity_keeps_ns_failure_cache_disabled() {
    let requests = Arc::new(Mutex::new(vec![]));
    let resolver = Resolver::new(
        Addresses {
            requests: requests.clone(),
            success: None,
        },
        ResolverConfig {
            root_servers: vec![addr(1)],
            cache_capacity: 0,
            ..ResolverConfig::default()
        },
    );
    for _ in 0..2 {
        assert!(
            lookup(&resolver, "ns.example.test.", false)
                .await
                .error
                .is_none()
        );
    }
    assert_eq!(requests.lock().unwrap().len(), 4);
    assert!(
        resolver
            .failure_cache
            .get(&q("ns.example.test.", QueryType::A), false)
            .is_none()
    );
}

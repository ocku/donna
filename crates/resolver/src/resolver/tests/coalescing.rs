use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use tokio::sync::Semaphore;
use transport::{Transport, TransportError, TransportProtocol};

use super::Resolver;
use crate::ResolverConfig;

#[derive(Clone)]
struct GatedTransport {
    calls: Arc<AtomicUsize>,
    release: Arc<Semaphore>,
    fail_first: Arc<AtomicBool>,
    ttl: u32,
}

impl GatedTransport {
    fn new(ttl: u32) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            release: Arc::new(Semaphore::new(0)),
            fail_first: Arc::new(AtomicBool::new(false)),
            ttl,
        }
    }

    fn failing_first() -> Self {
        Self {
            fail_first: Arc::new(AtomicBool::new(true)),
            ..Self::new(60)
        }
    }

    fn release(&self, count: usize) {
        self.release.add_permits(count);
    }
}

impl Transport for GatedTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.release.acquire().await.unwrap().forget();
            if call == 1 && self.fail_first.swap(false, Ordering::SeqCst) {
                return Err(TransportError::Io(std::io::Error::other(
                    "intentional first-call failure",
                )));
            }

            let question = &query.questions[0];
            let (rtype, rdata) = match question.qtype {
                QueryType::A => (RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 1))),
                QueryType::AAAA => (RecordType::AAAA, RData::AAAA(Ipv6Addr::LOCALHOST)),
                other => panic!("unsupported gated test query type: {other:?}"),
            };
            let class = match question.qclass {
                QClassType::Class(class) => class,
                _ => panic!("gated test requires a concrete class"),
            };
            Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: if class == ClassType::IN {
                    vec![ResourceRecord {
                        name: question.qname.clone(),
                        rtype,
                        class,
                        ttl: self.ttl,
                        rdata,
                    }]
                } else {
                    Vec::new()
                },
                authorities: Vec::new(),
                additionals: Vec::new(),
            })
        })
    }
}

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn question(labels: &[&str], qtype: QueryType, class: ClassType) -> Question {
    Question {
        qname: name(labels),
        qtype,
        qclass: QClassType::Class(class),
    }
}

fn config(cache_capacity: usize) -> ResolverConfig {
    ResolverConfig {
        root_servers: vec!["192.0.2.1:53".parse().unwrap()],
        max_steps: 1,
        max_attempts_per_server: 1,
        cache_capacity,
        ..ResolverConfig::default()
    }
}

async fn wait_for_calls(calls: &AtomicUsize, expected: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while calls.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("transport call did not start");
}

async fn wait_for_participants(
    resolver: &Resolver<GatedTransport>,
    question: &Question,
    expected: usize,
) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while resolver.in_flight.participant_count(question) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("callers did not join the in-flight entry");
}

#[tokio::test]
async fn identical_concurrent_calls_share_one_exchange_and_report_roles() {
    let transport = GatedTransport::new(60);
    let resolver = Arc::new(Resolver::new(transport.clone(), config(16)));
    let query = question(&["same", "example"], QueryType::A, ClassType::IN);

    let leader = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve_with_stats(query).await.unwrap() })
    };
    wait_for_calls(&transport.calls, 1).await;

    let mut followers = Vec::new();
    for _ in 0..7 {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        followers.push(tokio::spawn(async move {
            resolver.resolve_with_stats(query).await.unwrap()
        }));
    }
    wait_for_participants(&resolver, &query, 9).await;
    transport.release(1);

    let leader = leader.await.unwrap();
    assert_eq!(leader.stats().coalesced_leaders(), 1);
    assert_eq!(leader.stats().coalesced_followers(), 0);
    assert_eq!(leader.stats().udp_transmissions(), 1);
    for follower in followers {
        let follower = follower.await.unwrap();
        assert_eq!(
            follower.response().answers[0].rdata,
            leader.response().answers[0].rdata
        );
        assert_eq!(follower.stats().coalesced_leaders(), 0);
        assert_eq!(follower.stats().coalesced_followers(), 1);
        assert_eq!(follower.stats().udp_transmissions(), 0);
        assert!(follower.stats().coalesced_wait() > Duration::ZERO);
    }
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn case_distinct_concurrent_calls_preserve_each_callers_question() {
    let transport = GatedTransport::new(60);
    let resolver = Arc::new(Resolver::new(transport.clone(), config(16)));
    let leader_question = question(&["Mixed", "Example"], QueryType::A, ClassType::IN);
    let follower_question = question(&["mIXED", "eXAMPLE"], QueryType::A, ClassType::IN);

    let leader = {
        let resolver = Arc::clone(&resolver);
        let question = leader_question.clone();
        tokio::spawn(async move { resolver.resolve(question).await.unwrap() })
    };
    wait_for_calls(&transport.calls, 1).await;

    let follower = {
        let resolver = Arc::clone(&resolver);
        let question = follower_question.clone();
        tokio::spawn(async move { resolver.resolve(question).await.unwrap() })
    };
    wait_for_participants(&resolver, &follower_question, 3).await;
    transport.release(1);

    let leader_response = leader.await.unwrap();
    let follower_response = follower.await.unwrap();
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    assert_eq!(leader_response.questions.len(), 1);
    assert_eq!(follower_response.questions.len(), 1);
    assert_eq!(
        leader_response.questions[0].qname.as_ref(),
        leader_question.qname.as_ref()
    );
    assert_eq!(leader_response.questions[0].qtype, leader_question.qtype);
    assert_eq!(leader_response.questions[0].qclass, leader_question.qclass);
    assert_eq!(
        follower_response.questions[0].qname.as_ref(),
        follower_question.qname.as_ref()
    );
    assert_eq!(
        follower_response.questions[0].qtype,
        follower_question.qtype
    );
    assert_eq!(
        follower_response.questions[0].qclass,
        follower_question.qclass
    );
}

#[tokio::test]
async fn qname_qtype_and_qclass_are_independent_keys() {
    let transport = GatedTransport::new(60);
    let resolver = Arc::new(Resolver::new(transport.clone(), config(16)));
    let questions = [
        question(&["one", "example"], QueryType::A, ClassType::IN),
        question(&["two", "example"], QueryType::A, ClassType::IN),
        question(&["one", "example"], QueryType::AAAA, ClassType::IN),
        question(&["one", "example"], QueryType::A, ClassType::CH),
    ];

    let handles: Vec<_> = questions
        .iter()
        .cloned()
        .map(|query| {
            let resolver = Arc::clone(&resolver);
            tokio::spawn(async move { resolver.resolve(query).await })
        })
        .collect();
    wait_for_calls(&transport.calls, questions.len()).await;
    assert_eq!(resolver.in_flight.active_len(), questions.len());
    transport.release(questions.len());
    for handle in handles {
        handle.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn zero_ttl_success_is_shared_with_current_followers() {
    let transport = GatedTransport::new(0);
    let resolver = Arc::new(Resolver::new(transport.clone(), config(16)));
    let query = question(&["zero", "example"], QueryType::A, ClassType::IN);

    let leader = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve(query).await.unwrap() })
    };
    wait_for_calls(&transport.calls, 1).await;
    let follower = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve(query).await.unwrap() })
    };
    wait_for_participants(&resolver, &query, 3).await;
    transport.release(1);

    assert_eq!(
        leader.await.unwrap().answers[0].rdata,
        follower.await.unwrap().answers[0].rdata
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);

    let next = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve(query).await.unwrap() })
    };
    wait_for_calls(&transport.calls, 2).await;
    transport.release(1);
    next.await.unwrap();
    assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn canceled_leader_wakes_follower_and_allows_replacement_leader() {
    let transport = GatedTransport::new(60);
    let resolver = Arc::new(Resolver::new(transport.clone(), config(16)));
    let query = question(&["cancel", "example"], QueryType::A, ClassType::IN);

    let leader = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve(query).await })
    };
    wait_for_calls(&transport.calls, 1).await;
    let follower = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve_with_stats(query).await.unwrap() })
    };
    wait_for_participants(&resolver, &query, 3).await;

    leader.abort();
    assert!(leader.await.unwrap_err().is_cancelled());
    wait_for_calls(&transport.calls, 2).await;
    transport.release(1);
    let result = follower.await.unwrap();
    assert_eq!(result.stats().coalesced_followers(), 1);
    assert_eq!(result.stats().coalesced_leaders(), 1);
    assert_eq!(result.stats().udp_transmissions(), 1);
    assert_eq!(resolver.in_flight.active_len(), 0);
}

#[tokio::test]
async fn transport_failure_wakes_follower_to_retry_normal_admission() {
    let transport = GatedTransport::failing_first();
    let resolver = Arc::new(Resolver::new(transport.clone(), config(16)));
    let query = question(&["retry", "example"], QueryType::A, ClassType::IN);

    let first = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve(query).await })
    };
    wait_for_calls(&transport.calls, 1).await;
    let follower = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve_with_stats(query).await.unwrap() })
    };
    wait_for_participants(&resolver, &query, 3).await;

    transport.release(1);
    assert!(first.await.unwrap().is_err());
    wait_for_calls(&transport.calls, 2).await;
    transport.release(1);
    let result = follower.await.unwrap();
    assert_eq!(result.stats().coalesced_followers(), 1);
    assert_eq!(result.stats().coalesced_leaders(), 1);
    assert_eq!(result.stats().udp_transmissions(), 1);
}

#[tokio::test]
async fn full_table_bypasses_without_evicting_active_leader() {
    let transport = GatedTransport::new(0);
    let resolver = Arc::new(Resolver::new(transport.clone(), config(1)));
    let first_question = question(&["first", "example"], QueryType::A, ClassType::IN);
    let second_question = question(&["second", "example"], QueryType::A, ClassType::IN);

    let first = {
        let resolver = Arc::clone(&resolver);
        let question = first_question.clone();
        tokio::spawn(async move { resolver.resolve(question).await.unwrap() })
    };
    wait_for_calls(&transport.calls, 1).await;
    assert_eq!(resolver.in_flight.participant_count(&first_question), 2);

    let second = {
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move { resolver.resolve(second_question).await.unwrap() })
    };
    wait_for_calls(&transport.calls, 2).await;
    assert_eq!(resolver.in_flight.participant_count(&first_question), 2);
    assert_eq!(resolver.in_flight.active_len(), 1);

    transport.release(2);
    first.await.unwrap();
    second.await.unwrap();
}

#[derive(Clone)]
struct SelfLookupTransport {
    root: SocketAddr,
    delegated: SocketAddr,
    calls: Arc<AtomicUsize>,
    host: DomainName,
}

impl Transport for SelfLookupTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let (answers, authorities) = if call == 1 && server == self.root {
                (
                    Vec::new(),
                    vec![ResourceRecord {
                        name: name(&["example"]),
                        rtype: RecordType::NS,
                        class: ClassType::IN,
                        ttl: 60,
                        rdata: RData::NS(self.host.clone()),
                    }],
                )
            } else {
                (
                    vec![ResourceRecord {
                        name: self.host.clone(),
                        rtype: RecordType::A,
                        class: ClassType::IN,
                        ttl: 60,
                        rdata: RData::A(if server == self.delegated {
                            Ipv4Addr::new(192, 0, 2, 99)
                        } else {
                            Ipv4Addr::new(192, 0, 2, 53)
                        }),
                    }],
                    Vec::new(),
                )
            };
            Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: call != 1,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers,
                authorities,
                additionals: Vec::new(),
            })
        })
    }
}

#[tokio::test]
async fn internal_name_server_lookup_never_waits_on_public_key() {
    let root = "192.0.2.1:53".parse().unwrap();
    let delegated = "192.0.2.53:53".parse().unwrap();
    let host = name(&["ns", "example"]);
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver::new(
        SelfLookupTransport {
            root,
            delegated,
            calls: Arc::clone(&calls),
            host: host.clone(),
        },
        ResolverConfig {
            root_servers: vec![root],
            max_steps: 8,
            max_attempts_per_server: 1,
            cache_capacity: 16,
            ..ResolverConfig::default()
        },
    );

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        resolver.resolve_with_stats(Question {
            qname: host,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }),
    )
    .await
    .expect("internal lookup waited on its own public key")
    .unwrap();

    assert!(calls.load(Ordering::SeqCst) >= 2);
    assert_eq!(result.stats().coalesced_leaders(), 1);
    assert_eq!(result.stats().coalesced_followers(), 0);
}

use super::Resolver;
use crate::{ResolveError, ResolverConfig};
use dns::{ClassType, DomainName, Message, QClassType, QueryType, Question};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use transport::{Transport, TransportError, TransportProtocol};

struct Silent {
    protocol: Option<TransportProtocol>,
    calls: Arc<AtomicUsize>,
}
impl Transport for Silent {
    fn protocol(&self) -> Option<TransportProtocol> {
        self.protocol
    }
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        _: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(TransportError::Timeout)
        })
    }
}

#[tokio::test]
async fn every_transport_stops_after_three_transmissions_and_caches_exhaustion() {
    for protocol in [
        Some(TransportProtocol::Udp),
        Some(TransportProtocol::Tcp),
        Some(TransportProtocol::Tls),
        Some(TransportProtocol::Https),
        Some(TransportProtocol::Quic),
        Some(TransportProtocol::Dnscrypt),
        None,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::new(
            Silent {
                protocol,
                calls: calls.clone(),
            },
            ResolverConfig {
                root_servers: vec!["192.0.2.1:53".parse().unwrap()],
                max_attempts_per_server: 255,
                ..ResolverConfig::default()
            },
        );
        let question = Question {
            qname: DomainName::from_dotted("silent.example.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        for _ in 0..2 {
            let result = resolver.resolve(question.clone()).await;
            assert!(
                matches!(result, Err(ResolveError::NoReachableServer)),
                "{protocol:?}: {result:?}"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3, "{protocol:?}");
    }
}

struct CohostedHierarchy {
    protocol: TransportProtocol,
    calls: Arc<AtomicUsize>,
}
impl Transport for CohostedHierarchy {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(self.protocol)
    }
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            use dns::{Headers, RData, RecordType, ResourceRecord};
            if !query.questions[0]
                .qname
                .eq_dns(&DomainName::from_dotted("www.d.c.b.a.example.").unwrap())
            {
                return Err(TransportError::Timeout);
            }
            let step = self.calls.fetch_add(1, Ordering::SeqCst);
            let mut reply = Message {
                headers: Headers {
                    qr: true,
                    id: query.headers.id,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: vec![],
                authorities: vec![],
                additionals: vec![],
            };
            if step < 5 {
                let zone = [
                    "example.",
                    "a.example.",
                    "b.a.example.",
                    "c.b.a.example.",
                    "d.c.b.a.example.",
                ][step];
                let owner = DomainName::from_dotted(zone).unwrap();
                let ns = DomainName::from_dotted(&format!("ns.{zone}")).unwrap();
                reply.authorities.push(ResourceRecord {
                    name: owner,
                    rtype: RecordType::NS,
                    class: ClassType::IN,
                    ttl: 300,
                    rdata: RData::NS(ns.clone()),
                });
                reply.additionals.push(ResourceRecord {
                    name: ns,
                    rtype: RecordType::A,
                    class: ClassType::IN,
                    ttl: 300,
                    rdata: RData::A(match server.ip() {
                        std::net::IpAddr::V4(ip) => ip,
                        _ => unreachable!(),
                    }),
                });
            } else {
                reply.headers.aa = true;
                reply.answers.push(ResourceRecord {
                    name: query.questions[0].qname.clone(),
                    rtype: RecordType::A,
                    class: ClassType::IN,
                    ttl: 60,
                    rdata: RData::A("192.0.2.80".parse().unwrap()),
                });
            }
            Ok(reply)
        })
    }
}
#[tokio::test]
async fn useful_progress_preserves_more_than_three_cohosted_delegation_cuts() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver::new(
        CohostedHierarchy {
            protocol: TransportProtocol::Udp,
            calls: calls.clone(),
        },
        ResolverConfig {
            root_servers: vec!["192.0.2.1:53".parse().unwrap()],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let reply = resolver
        .resolve(Question {
            qname: DomainName::from_dotted("www.d.c.b.a.example.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 6);
}

struct TruncatedHierarchy<T> {
    timeout: bool,
    next: T,
    udp_calls: Arc<AtomicUsize>,
}
impl<T: Transport> Transport for TruncatedHierarchy<T> {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }
    fn transition(&self, reason: transport::TransitionReason) -> Option<&dyn Transport> {
        (reason
            == if self.timeout {
                transport::TransitionReason::Timeout
            } else {
                transport::TransitionReason::TruncatedResponse
            })
        .then_some(&self.next)
    }
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            if self.timeout
                && !query.questions[0]
                    .qname
                    .eq_dns(&DomainName::from_dotted("www.d.c.b.a.example.").unwrap())
            {
                return Err(TransportError::Timeout);
            }
            self.udp_calls.fetch_add(1, Ordering::SeqCst);
            if self.timeout {
                return Err(TransportError::Timeout);
            }
            Ok(Message {
                headers: dns::Headers {
                    id: query.headers.id,
                    qr: true,
                    tc: true,
                    ..dns::Headers::default()
                },
                questions: query.questions.clone(),
                answers: vec![],
                authorities: vec![],
                additionals: vec![],
            })
        })
    }
}
#[tokio::test]
async fn accepted_tcp_progress_restores_only_its_successful_truncation_path() {
    let calls = Arc::new(AtomicUsize::new(0));
    let udp_calls = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver::new(
        TruncatedHierarchy {
            timeout: false,
            next: CohostedHierarchy {
                protocol: TransportProtocol::Tcp,
                calls: calls.clone(),
            },
            udp_calls: udp_calls.clone(),
        },
        ResolverConfig {
            root_servers: vec!["192.0.2.1:53".parse().unwrap()],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let reply = resolver
        .resolve(Question {
            qname: DomainName::from_dotted("www.d.c.b.a.example.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    assert_eq!(udp_calls.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn truncation_followed_by_failed_tcp_does_not_restore_udp_or_root_budget() {
    let calls = Arc::new(AtomicUsize::new(0));
    let udp_calls = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver::new(
        TruncatedHierarchy {
            timeout: false,
            next: Silent {
                protocol: Some(TransportProtocol::Tcp),
                calls: calls.clone(),
            },
            udp_calls: udp_calls.clone(),
        },
        ResolverConfig {
            root_servers: vec!["192.0.2.1:53".parse().unwrap()],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let question = Question {
        qname: DomainName::from_dotted("silent.example.").unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    for _ in 0..2 {
        assert!(matches!(
            resolver.resolve(question.clone()).await,
            Err(ResolveError::NoReachableServer)
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(udp_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn useful_tcp_response_never_resurrects_a_timeout_failed_udp_protocol() {
    let calls = Arc::new(AtomicUsize::new(0));
    let udp_calls = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver::new(
        TruncatedHierarchy {
            timeout: true,
            next: CohostedHierarchy {
                protocol: TransportProtocol::Tcp,
                calls: calls.clone(),
            },
            udp_calls: udp_calls.clone(),
        },
        ResolverConfig {
            root_servers: vec!["192.0.2.1:53".parse().unwrap()],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let result = resolver
        .resolve(Question {
            qname: DomainName::from_dotted("www.d.c.b.a.example.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await;
    assert!(
        matches!(result, Err(ResolveError::NoReachableServer)),
        "{result:?}"
    );
    assert_eq!(udp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

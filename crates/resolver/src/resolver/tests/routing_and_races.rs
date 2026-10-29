use super::*;

#[tokio::test]
async fn races_candidates_and_takes_the_first_reply() {
    // The slow server is popped first, so sequential querying would return its
    // answer; racing must instead return the fast server's without waiting.
    let slow = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let fast = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53));
    let transport = RacingTransport {
        slow_server: slow,
        delay: Duration::from_millis(50),
    };
    let resolver = Resolver::new(
        transport,
        ResolverConfig {
            max_concurrent_queries: 2,
            ..config(vec![fast, slow])
        },
    );

    let reply = resolver
        .resolve(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 2))
    );
}

#[derive(Clone)]
struct LearningTransport {
    fast_server: SocketAddr,
    calls: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Transport for LearningTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(server);
            let (delay, headers, answers) = if server == self.fast_server {
                (
                    Duration::from_millis(10),
                    Headers {
                        id: query.headers.id,
                        qr: true,
                        rcode: RCode::ServerFailure,
                        ..Headers::default()
                    },
                    Vec::new(),
                )
            } else {
                (
                    Duration::from_millis(50),
                    Headers {
                        id: query.headers.id,
                        qr: true,
                        aa: true,
                        ..Headers::default()
                    },
                    vec![address_record(query.questions[0].qname.clone(), 42)],
                )
            };
            tokio::time::sleep(delay).await;
            let mut reply = response(headers, answers);
            reply.questions.clone_from(&query.questions);
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn measured_rtt_makes_the_faster_reachable_server_the_next_first_pop() {
    let fast = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let slow = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        LearningTransport {
            fast_server: fast,
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![fast, slow],
            max_concurrent_queries: 2,
            max_attempts_per_server: 1,
            cache_capacity: 0,
            ..ResolverConfig::default()
        },
    );

    let warmup = resolver
        .resolve_with_stats(question(&["warmup", "example"]))
        .await
        .unwrap();
    assert_eq!(warmup.stats().server_latency_samples(), 2);
    resolver
        .resolve(question(&["measured", "example"]))
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls[2], fast,
        "the learned fast server must be popped first"
    );
}

#[derive(Clone, Copy)]
enum CorrelatedUnusableReply {
    ServerFailure,
    MalformedCname,
}

#[derive(Clone)]
struct CorrelatedUnusableRaceTransport {
    fast_server: SocketAddr,
    slow_server: SocketAddr,
    slow_ready: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<SocketAddr>>>,
    unusable_reply: CorrelatedUnusableReply,
}

impl Transport for CorrelatedUnusableRaceTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(server);
            if server == self.slow_server {
                poll_fn(|cx| {
                    if self.slow_ready.load(Ordering::SeqCst) {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                let mut reply = response(
                    Headers {
                        id: query.headers.id,
                        qr: true,
                        aa: true,
                        ..Headers::default()
                    },
                    vec![address_record(query.questions[0].qname.clone(), 42)],
                );
                reply.questions.clone_from(&query.questions);
                return Ok(reply);
            }

            assert_eq!(server, self.fast_server);
            self.slow_ready.store(true, Ordering::SeqCst);
            let mut reply = match self.unusable_reply {
                CorrelatedUnusableReply::ServerFailure => response(
                    Headers {
                        id: query.headers.id,
                        qr: true,
                        rcode: RCode::ServerFailure,
                        ..Headers::default()
                    },
                    Vec::new(),
                ),
                CorrelatedUnusableReply::MalformedCname => {
                    let owner = query.questions[0].qname.clone();
                    let cname = |last_label: &[u8]| ResourceRecord {
                        name: owner.clone(),
                        rtype: RecordType::CNAME,
                        class: ClassType::IN,
                        ttl: 60,
                        rdata: RData::CNAME(
                            DomainName::from_labels(vec![last_label.to_vec(), b"example".to_vec()])
                                .unwrap(),
                        ),
                    };
                    response(
                        Headers {
                            id: query.headers.id,
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![cname(b"first"), cname(b"second")],
                    )
                }
            };
            reply.questions.clone_from(&query.questions);
            Ok(reply)
        })
    }
}

async fn assert_correlated_unusable_reply_preserves_in_flight_answer(
    unusable_reply: CorrelatedUnusableReply,
) {
    let fast = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let slow = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        CorrelatedUnusableRaceTransport {
            fast_server: fast,
            slow_server: slow,
            slow_ready: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&calls),
            unusable_reply,
        },
        ResolverConfig {
            root_servers: vec![fast, slow],
            max_steps: 2,
            max_attempts_per_server: 1,
            max_concurrent_queries: 2,
            ..ResolverConfig::default()
        },
    );

    let result = resolver
        .resolve_with_stats(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(
        result.response().answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 42))
    );
    assert_eq!(
        result.stats().server_latency_samples(),
        match unusable_reply {
            CorrelatedUnusableReply::ServerFailure => 2,
            CorrelatedUnusableReply::MalformedCname => 1,
        }
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.iter().filter(|server| **server == fast).count(), 1);
    assert_eq!(calls.iter().filter(|server| **server == slow).count(), 1);
}

#[tokio::test]
async fn correlated_server_failure_does_not_cancel_an_in_flight_answer() {
    assert_correlated_unusable_reply_preserves_in_flight_answer(
        CorrelatedUnusableReply::ServerFailure,
    )
    .await;
}

#[tokio::test]
async fn malformed_correlated_noerror_does_not_cancel_an_in_flight_answer() {
    assert_correlated_unusable_reply_preserves_in_flight_answer(
        CorrelatedUnusableReply::MalformedCname,
    )
    .await;
}

#[derive(Clone)]
struct AllServerFailureTransport {
    calls: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Transport for AllServerFailureTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(server);
            let mut reply = response(
                Headers {
                    id: query.headers.id,
                    qr: true,
                    rcode: RCode::ServerFailure,
                    ..Headers::default()
                },
                Vec::new(),
            );
            reply.questions.clone_from(&query.questions);
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn all_correlated_unusable_replies_keep_temporary_failure_classification() {
    let first = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let second = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        AllServerFailureTransport {
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![first, second],
            max_steps: 3,
            max_attempts_per_server: 1,
            max_concurrent_queries: 2,
            ..ResolverConfig::default()
        },
    );

    assert!(matches!(
        resolver.resolve(question(&["www", "example"])).await,
        Err(ResolveError::TemporaryServerFailure)
    ));
    let calls = calls.lock().unwrap();
    assert_eq!(calls.iter().filter(|server| **server == first).count(), 1);
    assert_eq!(calls.iter().filter(|server| **server == second).count(), 1);
}

#[derive(Clone)]
struct ReferralCancelsRaceTransport {
    fast_root: SocketAddr,
    slow_root: SocketAddr,
    delegated_server: SocketAddr,
    slow_ready: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Transport for ReferralCancelsRaceTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(server);
            if server == self.slow_root {
                poll_fn(|cx| {
                    if self.slow_ready.load(Ordering::SeqCst) {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                let mut stale = response(
                    Headers {
                        id: query.headers.id,
                        qr: true,
                        aa: true,
                        ..Headers::default()
                    },
                    vec![address_record(query.questions[0].qname.clone(), 99)],
                );
                stale.questions.clone_from(&query.questions);
                return Ok(stale);
            }
            if server == self.fast_root {
                self.slow_ready.store(true, Ordering::SeqCst);
                let mut referral = referral_response(
                    name(&["example"]),
                    name(&["ns", "example"]),
                    match self.delegated_server.ip() {
                        std::net::IpAddr::V4(address) => address.octets()[3],
                        std::net::IpAddr::V6(_) => unreachable!("test server is IPv4"),
                    },
                );
                referral.headers.id = query.headers.id;
                referral.questions.clone_from(&query.questions);
                return Ok(referral);
            }

            assert_eq!(server, self.delegated_server);
            let mut answer = response(
                Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![address_record(query.questions[0].qname.clone(), 42)],
            );
            answer.questions.clone_from(&query.questions);
            Ok(answer)
        })
    }
}

#[tokio::test]
async fn progressing_referral_cancels_obsolete_in_flight_exchanges() {
    let fast_root = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 53));
    let slow_root = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 2), 53));
    let delegated_server = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        ReferralCancelsRaceTransport {
            fast_root,
            slow_root,
            delegated_server,
            slow_ready: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![fast_root, slow_root],
            max_steps: 3,
            max_attempts_per_server: 1,
            max_concurrent_queries: 2,
            ..ResolverConfig::default()
        },
    );

    let result = resolver
        .resolve_with_stats(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(
        result.response().answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 42))
    );
    assert_eq!(result.stats().server_latency_samples(), 2);
    assert_eq!(result.stats().server_timeout_penalties(), 0);
    assert_eq!(result.stats().server_io_penalties(), 0);
    assert_eq!(result.stats().canceled_losers(), 1);
    assert_eq!(
        *calls.lock().unwrap(),
        [slow_root, fast_root, delegated_server]
    );
}

#[tokio::test]
async fn a_fast_transport_failure_does_not_win_the_race() {
    // A server that fails instantly must not cancel a slower in-flight reply.
    struct FailingTransport {
        failing_server: SocketAddr,
        delay: Duration,
    }

    impl Transport for FailingTransport {
        fn exchange<'future>(
            &'future self,
            server: SocketAddr,
            query: &'future Message,
            _timeout: Duration,
        ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
            Box::pin(async move {
                if server == self.failing_server {
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "refused",
                    )));
                }
                tokio::time::sleep(self.delay).await;
                let mut reply = response(
                    Headers {
                        id: query.headers.id,
                        qr: true,
                        aa: true,
                        ..Headers::default()
                    },
                    vec![address_record(query.questions[0].qname.clone(), 9)],
                );
                reply.questions = query.questions.clone();
                Ok(reply)
            })
        }
    }

    let failing = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let working = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53));
    let resolver = Resolver::new(
        FailingTransport {
            failing_server: failing,
            delay: Duration::from_millis(50),
        },
        ResolverConfig {
            max_concurrent_queries: 2,
            ..config(vec![working, failing])
        },
    );

    let result = resolver
        .resolve_with_stats(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(
        result.response().answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 9))
    );
    assert_eq!(result.stats().server_io_penalties(), 1);
    assert_eq!(result.stats().server_timeout_penalties(), 0);
    assert_eq!(result.stats().server_latency_samples(), 1);
}

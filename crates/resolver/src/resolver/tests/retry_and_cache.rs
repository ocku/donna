use super::*;

#[tokio::test]
async fn tries_another_server_when_answers_do_not_match_the_question() {
    // RFC 1035 §6.1.4.2 (§7.3): data whose owner or class does not match the
    // question is not an answer and must not terminate resolution.
    let query = question(&["www", "example"]);
    let mut chaos = address_record(query.qname.clone(), 1);
    chaos.class = ClassType::CH;
    let unrelated = address_record(name(&["other", "example"]), 2);
    let answer = address_record(query.qname.clone(), 3);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![unrelated],
            ),
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![chaos],
            ),
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![answer],
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(
        transport,
        config(vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
            "192.0.2.3:53".parse().unwrap(),
        ]),
    );

    let reply = resolver.resolve(query).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert!(reply.answers[0].name.eq_dns(&name(&["www", "example"])));
    assert_eq!(reply.answers[0].class, ClassType::IN);
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn tries_another_server_after_retryable_error_responses() {
    // RFC 1035 §4.1.1: RCODE values other than NOERROR and Name Error do not
    // answer the question; one server's failure must not end resolution while
    // other delegation hosts remain untried.
    let query = question(&["www", "example"]);
    let answer = address_record(query.qname.clone(), 1);
    let refused = response(
        Headers {
            qr: true,
            aa: true,
            rcode: RCode::Refused,
            ..Headers::default()
        },
        Vec::new(),
    );
    let format_error = response(
        Headers {
            qr: true,
            rcode: RCode::FormatError,
            ..Headers::default()
        },
        Vec::new(),
    );
    let not_authoritative = response(
        Headers {
            qr: true,
            rcode: RCode::NotAuthoritative,
            ..Headers::default()
        },
        Vec::new(),
    );
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            refused,
            format_error,
            not_authoritative,
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![answer],
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(
        transport,
        config(vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
            "192.0.2.3:53".parse().unwrap(),
            "192.0.2.4:53".parse().unwrap(),
        ]),
    );

    let reply = resolver.resolve(query).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(requests.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn returns_temporary_failure_after_reachable_servers_return_dns_errors() {
    let query = question(&["www", "example"]);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            response(
                Headers {
                    qr: true,
                    rcode: RCode::Refused,
                    ..Headers::default()
                },
                Vec::new(),
            ),
            response(
                Headers {
                    qr: true,
                    rcode: RCode::ServerFailure,
                    ..Headers::default()
                },
                Vec::new(),
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(
        transport,
        config(vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        ]),
    );

    assert!(matches!(
        resolver.resolve(query).await,
        Err(ResolveError::TemporaryServerFailure)
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn discards_a_response_with_a_mismatched_question_count() {
    // RFC 1035 §7.3: the response is matched to the outstanding query via its
    // question section; a reply echoing anything but that one question is
    // discarded.
    let query = question(&["www", "example"]);
    let answer = address_record(query.qname.clone(), 1);
    let mut two_questions = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![answer.clone()],
    );
    two_questions.questions = vec![query.clone(), question(&["other", "example"])];
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            two_questions,
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![answer],
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(
        transport,
        config(vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        ]),
    );

    let reply = resolver.resolve(query).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(requests.lock().unwrap().len(), 2);
}

/// The server at `fast_server` answers instantly with a reply for a different
/// transaction ID; every other server delays before answering correctly.
#[derive(Clone)]
struct UnusableWinnerTransport {
    fast_server: SocketAddr,
    delay: Duration,
}

impl Transport for UnusableWinnerTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let won_with_an_unusable_reply = server == self.fast_server;
            if won_with_an_unusable_reply {
                // Let the valid candidate reserve its transmission before this
                // unusable reply completes, making cancellation observable under
                // the exact two-transmission work budget below.
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(self.delay).await;
            }
            let id = if won_with_an_unusable_reply {
                query.headers.id.wrapping_add(1)
            } else {
                query.headers.id
            };
            let last_octet = if won_with_an_unusable_reply { 9 } else { 1 };
            let mut reply = response(
                Headers {
                    id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![address_record(query.questions[0].qname.clone(), last_octet)],
            );
            reply.questions = query.questions.clone();
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn retries_race_losers_cancelled_by_an_unusable_winning_reply() {
    // RFC 1035 §4.2.1 and §7.2: a server whose in-flight reply was cancelled
    // when another server won the race must still be queried before the
    // resolution gives up; otherwise a single mismatched fast reply ends the
    // resolution with NoReachableServer despite an untried server.
    let fast = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let slow = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53));
    let transport = UnusableWinnerTransport {
        fast_server: fast,
        delay: Duration::from_millis(50),
    };
    let resolver = Resolver::new(
        transport,
        ResolverConfig {
            max_steps: 2,
            max_attempts_per_server: 1,
            max_concurrent_queries: 2,
            ..config(vec![slow, fast])
        },
    );

    let reply = resolver
        .resolve(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
}

/// Refuses every UDP exchange as oversized but answers over TCP.
#[derive(Clone)]
struct OversizedUdpTransport;

impl Transport for OversizedUdpTransport {
    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        _query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            Err(TransportError::MessageTooLong {
                length: 4097,
                maximum: 4096,
            })
        })
    }
}

#[derive(Clone)]
struct SuccessfulTransitionTransport;

impl Transport for SuccessfulTransitionTransport {
    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let mut reply = response(
                Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![address_record(query.questions[0].qname.clone(), 1)],
            );
            reply.questions = query.questions.clone();
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn retries_oversized_udp_queries_over_tcp_with_consistent_work_accounting() {
    // RFC 1035 §4.2.1: a query too large for the datagram transport must be
    // retried over TCP at the same server, not abandoned.
    let resolver = Resolver::new(
        TransportRoute::new(OversizedUdpTransport).on(
            [TransitionReason::QueryTooLarge],
            SuccessfulTransitionTransport,
        ),
        config(vec!["192.0.2.53:53".parse().unwrap()]),
    );

    let reply = resolver
        .resolve(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(reply.answers.len(), 1);

    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_steps = 1;
    let resolver = Resolver::new(
        TransportRoute::new(OversizedUdpTransport).on(
            [TransitionReason::QueryTooLarge],
            SuccessfulTransitionTransport,
        ),
        settings,
    );
    assert!(matches!(
        resolver.resolve(question(&["www", "example"])).await,
        Err(ResolveError::WorkLimitExceeded)
    ));
}

#[tokio::test]
async fn serves_a_repeat_query_from_the_response_cache() {
    // RFC 1035 §7.4: a complete answer for the question may be cached and must
    // satisfy a later identical query without another transmission.
    let query = question(&["www", "example"]);
    let answer = address_record(query.qname.clone(), 1);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![answer],
        )])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let first = resolver.resolve_with_stats(query.clone()).await.unwrap();
    let second = resolver.resolve_with_stats(query).await.unwrap();

    assert_eq!(first.response().answers.len(), 1);
    assert_eq!(second.response().answers.len(), 1);
    assert_eq!(first.stats().udp_transmissions(), 1);
    assert_eq!(first.stats().response_rounds(), 1);
    assert_eq!(first.stats().final_cache_source(), None);
    assert_eq!(second.stats().udp_transmissions(), 0);
    assert_eq!(second.stats().response_rounds(), 0);
    assert_eq!(
        second.stats().final_cache_source(),
        Some(ResolutionCacheSource::Positive)
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn serves_an_iteratively_learned_answer_without_followup_transport() {
    // Model the normal root -> TLD -> authoritative path. A repeat must use
    // the final positive answer directly, rather than merely starting from a
    // cached delegation and contacting the authoritative server again.
    let query = question(&["www", "example", "com"]);
    let root_referral = referral_response(name(&["com"]), name(&["ns", "com"]), 2);
    let tld_referral = referral_response(
        name(&["example", "com"]),
        name(&["ns", "example", "com"]),
        3,
    );
    let authoritative = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 80)],
    );
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![root_referral, tld_referral, authoritative])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.1:53".parse().unwrap()]));

    let first = resolver.resolve_with_stats(query.clone()).await.unwrap();
    let exchanges_after_first = requests.lock().unwrap().len();
    let cached = resolver.resolve_with_stats(query).await.unwrap();

    assert_eq!(exchanges_after_first, 3);
    assert_eq!(requests.lock().unwrap().len(), exchanges_after_first);
    assert_eq!(first.response().answers.len(), 1);
    assert_eq!(cached.response().answers.len(), 1);
    assert!(cached.response().answers[0].eq_dns(&first.response().answers[0]));
    assert_eq!(first.stats().udp_transmissions(), 3);
    assert_eq!(first.stats().response_rounds(), 3);
    assert_eq!(first.stats().referrals_followed(), 2);
    assert_eq!(first.stats().name_server_lookups(), 0);
    assert_eq!(cached.stats().udp_transmissions(), 0);
    assert_eq!(
        cached.stats().final_cache_source(),
        Some(ResolutionCacheSource::Positive)
    );
}

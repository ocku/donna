use super::*;

#[test]
fn delegation_progress_requires_a_strict_descendant() {
    let root = DomainName::root();
    let example = name(&["example"]);
    let child = name(&["child", "example"]);

    assert!(delegation_progresses(&root, &example));
    assert!(delegation_progresses(&example, &child));
    assert!(!delegation_progresses(&root, &root));
    assert!(!delegation_progresses(&example, &name(&["EXAMPLE"])));
    assert!(!delegation_progresses(&child, &example));
    assert!(!delegation_progresses(&example, &name(&["other"])));
}

#[tokio::test]
async fn rejects_ixfr_before_building_or_sending_a_query() {
    let mut query = question(&["example"]);
    query.qtype = QueryType::IXFR;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(Vec::new())),
        requests: Arc::clone(&requests),
    };
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    assert!(matches!(
        resolver.resolve(query).await,
        Err(ResolveError::UnsupportedQuestion)
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_semantically_invalid_messages_from_custom_transports() {
    let query = question(&["www", "example"]);
    // An A record whose RDATA does not match its type can never be decoded
    // from the wire; custom transports must not bypass that semantic check.
    let answer = ResourceRecord {
        rdata: RData::Unknown(Vec::new()),
        ..address_record(query.qname.clone(), 1)
    };
    let reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![answer],
    );
    assert!(reply.validate_strict().is_err());

    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![reply])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    assert!(matches!(
        resolver.resolve(query).await,
        Err(ResolveError::NoReachableServer)
    ));
}

#[tokio::test]
async fn rejects_explicitly_mismatched_ids_and_questions() {
    let query = question(&["www", "example"]);
    let answer = address_record(query.qname.clone(), 1);
    let wrong_id = response(
        Headers {
            id: u16::MAX,
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![answer.clone()],
    );
    let mut wrong_question = response(
        Headers {
            id: 7,
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![answer.clone()],
    );
    wrong_question.questions = vec![question(&["other", "example"])];
    let valid = response(
        Headers {
            id: 7,
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![answer],
    );
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![wrong_id, wrong_question, valid])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new_with_id_source(
        transport,
        config(vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
            "192.0.2.3:53".parse().unwrap(),
        ]),
        || 7,
    );

    let reply = resolver.resolve(query).await.unwrap();
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn rejects_a_response_that_remains_truncated_after_tcp_fallback() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        truncation_route(Arc::clone(&calls), true),
        config(vec!["192.0.2.53:53".parse().unwrap()]),
    );

    assert!(matches!(
        resolver.resolve(question(&["www", "example"])).await,
        Err(ResolveError::NoReachableServer)
    ));
    assert_eq!(*calls.lock().unwrap(), ["udp", "tcp"]);
}

#[tokio::test]
async fn tcp_initial_transport_does_not_count_as_a_udp_transmission() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_steps = 1;
    settings.max_attempts_per_server = 1;
    let resolver = Resolver::new(
        CompletingTransport {
            calls: Arc::clone(&calls),
            tcp_truncated: false,
        },
        settings,
    );

    let result = resolver
        .resolve_with_stats(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(result.response().answers.len(), 1);
    assert_eq!(result.stats().udp_transmissions(), 0);
    assert_eq!(*calls.lock().unwrap(), ["tcp"]);
}

#[tokio::test]
async fn accepts_a_complete_response_after_tcp_fallback() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_attempts_per_server = 1;
    let resolver = Resolver::new(truncation_route(Arc::clone(&calls), false), settings);

    let result = resolver
        .resolve_with_stats(question(&["www", "example"]))
        .await
        .unwrap();
    assert_eq!(result.response().answers.len(), 1);
    assert_eq!(result.stats().udp_transmissions(), 1);
    assert_eq!(result.stats().tcp_transitions(), 1);
    assert_eq!(result.stats().tcp_completions(), 1);
    assert_eq!(*calls.lock().unwrap(), ["udp", "tcp"]);
}

#[tokio::test]
async fn follows_reasoned_multi_protocol_transitions() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let cleartext_downgrade = RoutedTestTransport {
        name: "udp",
        protocol: Some(TransportProtocol::Udp),
        outcome: RoutedOutcome::Complete,
        calls: Arc::clone(&calls),
    };
    let encrypted_route = TransportRoute::new(RoutedTestTransport {
        name: "dot",
        protocol: None,
        outcome: RoutedOutcome::IoError,
        calls: Arc::clone(&calls),
    })
    .on([TransitionReason::IoError], cleartext_downgrade);
    let route = TransportRoute::new(RoutedTestTransport {
        name: "doh",
        protocol: None,
        outcome: RoutedOutcome::Timeout,
        calls: Arc::clone(&calls),
    })
    .on([TransitionReason::Timeout], encrypted_route);
    let resolver = Resolver::new(route, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let result = resolver
        .resolve_with_stats(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(result.response().answers.len(), 1);
    assert_eq!(result.stats().udp_transmissions(), 1);
    assert_eq!(result.stats().tcp_transitions(), 0);
    assert_eq!(result.stats().tcp_completions(), 0);
    assert_eq!(*calls.lock().unwrap(), ["doh", "dot", "udp"]);
}

#[tokio::test]
async fn tcp_to_udp_transition_counts_only_the_udp_transmission() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let route = TransportRoute::new(RoutedTestTransport {
        name: "tcp",
        protocol: Some(TransportProtocol::Tcp),
        outcome: RoutedOutcome::Timeout,
        calls: Arc::clone(&calls),
    })
    .on(
        [TransitionReason::Timeout],
        RoutedTestTransport {
            name: "udp",
            protocol: Some(TransportProtocol::Udp),
            outcome: RoutedOutcome::Complete,
            calls: Arc::clone(&calls),
        },
    );
    let resolver = Resolver::new(route, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let result = resolver
        .resolve_with_stats(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(result.response().answers.len(), 1);
    assert_eq!(result.stats().udp_transmissions(), 1);
    assert_eq!(result.stats().tcp_transitions(), 0);
    assert_eq!(result.stats().tcp_completions(), 0);
    assert_eq!(*calls.lock().unwrap(), ["tcp", "udp"]);
}

#[tokio::test]
async fn detects_cname_loops_without_exhausting_the_work_limit() {
    let original = question(&["a", "example"]);
    let alternate = name(&["b", "example"]);
    let cname = |owner: DomainName, target: DomainName| ResourceRecord {
        name: owner,
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            response(
                Headers {
                    qr: true,
                    ..Headers::default()
                },
                vec![cname(original.qname.clone(), alternate.clone())],
            ),
            response(
                Headers {
                    qr: true,
                    ..Headers::default()
                },
                vec![cname(alternate, name(&["A", "EXAMPLE"]))],
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    assert!(matches!(
        resolver.resolve(original).await,
        Err(ResolveError::CnameLoop)
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn answers_a_qtype_cname_query_without_following_the_target() {
    // RFC 1035 §3.2.3: QTYPE CNAME matches CNAME RRs at the QNAME; the query
    // must be answered directly instead of restarting at the canonical name.
    let mut original = question(&["www", "example"]);
    original.qtype = QueryType::CNAME;
    let target = name(&["origin", "example"]);
    let cname = ResourceRecord {
        name: original.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target.clone()),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![cname],
        )])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let reply = resolver.resolve(original.clone()).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].rtype, RecordType::CNAME);
    assert!(reply.answers[0].name.eq_dns(&original.qname));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn detects_a_self_referencing_cname_in_a_single_packet() {
    // A CNAME whose target is its own owner is a one-record loop; it must be
    // reported instead of restarting the query at the same name forever.
    let original = question(&["www", "example"]);
    let cname = ResourceRecord {
        name: original.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(original.qname.clone()),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![response(
            Headers {
                qr: true,
                ..Headers::default()
            },
            vec![cname],
        )])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    assert!(matches!(
        resolver.resolve(original).await,
        Err(ResolveError::CnameLoop)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn answers_a_qtype_any_query_with_a_cname_without_following_it() {
    // RFC 1035 §3.2.3: QTYPE * matches every record type, so a CNAME at the
    // QNAME is itself the answer and must not restart the query at its target.
    let original = question(&["www", "example"]);
    let mut query = original.clone();
    query.qtype = QueryType::ANY;
    let target = name(&["origin", "example"]);
    let cname = ResourceRecord {
        name: original.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target.clone()),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![cname],
        )])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let reply = resolver.resolve(query).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].rtype, RecordType::CNAME);
    assert!(reply.answers[0].name.eq_dns(&original.qname));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn caches_any_answers_under_their_actual_record_types() {
    let original = question(&["www", "example"]);
    let mut query = original.clone();
    query.qtype = QueryType::ANY;
    let text = ResourceRecord {
        name: original.qname.clone(),
        rtype: RecordType::TXT,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::TXT(vec![b"v=spf1".to_vec()]),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![text],
        )])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let reply = resolver.resolve(query).await.unwrap();
    let mut text_query = original;
    text_query.qtype = QueryType::TXT;
    let cached = resolver.resolve(text_query).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].rtype, RecordType::TXT);
    assert_eq!(cached.answers.len(), 1);
    assert_eq!(cached.answers[0].rtype, RecordType::TXT);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn does_not_cache_results_for_a_wildcard_qname() {
    // RFC 1035 §7.4: results for QNAMEs containing "*" labels must not be
    // cached, because the cache lacks the zone data needed to bound wildcards.
    let query = question(&["*", "example"]);
    let answer = address_record(query.qname.clone(), 1);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![answer.clone()],
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
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let first = resolver.resolve(query.clone()).await.unwrap();
    let second = resolver.resolve(query).await.unwrap();

    assert_eq!(first.answers.len(), 1);
    assert_eq!(second.answers.len(), 1);
    assert_eq!(requests.lock().unwrap().len(), 2);
}

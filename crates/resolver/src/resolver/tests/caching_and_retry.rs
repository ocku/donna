use super::*;

#[tokio::test]
async fn uses_matching_in_bailiwick_additional_data_for_the_current_request() {
    let query = question(&["www", "example"]);
    let name_server = name(&["ns", "example"]);
    let referral = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: name(&["example"]),
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::NS(name_server.clone()),
        }],
        additionals: vec![address_record(name_server.clone(), 9)],
    };
    let answer = address_record(query.qname.clone(), 1);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            referral,
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
    let resolver = Resolver::new(transport, config(vec!["192.0.2.1:53".parse().unwrap()]));

    let reply = resolver.resolve(query.clone()).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].questions[0].qname.eq_dns(&query.qname));
}

#[tokio::test]
async fn caches_the_requested_rrset_without_promoting_unrelated_data() {
    let query = question(&["www", "example"]);
    let answer = ResourceRecord {
        name: query.qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let unrelated = ResourceRecord {
        name: name(&["other", "example"]),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
    };
    let mut first = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![answer, unrelated],
    );
    first.authorities = vec![ResourceRecord {
        name: name(&["example"]),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(name(&["ns", "example"])),
    }];
    first.additionals = vec![address_record(name(&["ns", "example"]), 53)];
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            referral_response(name(&["example"]), name(&["ns", "example"]), 53),
            first,
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let first = resolver.resolve(query.clone()).await.unwrap();
    let second = resolver.resolve(query).await.unwrap();

    assert_eq!(requests.lock().unwrap().len(), 2);
    for reply in [first, second] {
        assert_eq!(reply.answers.len(), 1);
        assert!(reply.authorities.is_empty());
        assert!(reply.additionals.is_empty());
    }
}

#[tokio::test]
async fn retransmits_to_a_server_after_a_timeout() {
    let query = question(&["www", "example"]);
    let reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![ResourceRecord {
            name: query.qname.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }],
    );
    let attempts = Arc::new(Mutex::new(0));
    let transport = RetryTransport {
        attempts: Arc::clone(&attempts),
        reply,
    };
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let result = resolver.resolve_with_stats(query).await.unwrap();

    assert_eq!(result.response().headers.rcode, RCode::Ok);
    assert_eq!(result.stats().timeouts(), 1);
    assert_eq!(result.stats().server_timeout_penalties(), 1);
    assert_eq!(result.stats().server_io_penalties(), 0);
    assert_eq!(result.stats().server_latency_samples(), 1);
    assert_eq!(result.stats().udp_transmissions(), 2);
    assert_eq!(result.stats().response_rounds(), 2);
    assert_eq!(*attempts.lock().unwrap(), 2);
}

#[tokio::test]
async fn tcp_retry_is_not_limited_by_the_udp_attempt_budget() {
    let query = question(&["www", "example"]);
    let calls = Arc::new(Mutex::new(0));
    let transport = TcpRetryTransport {
        calls: Arc::clone(&calls),
        reply: response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 1)],
        ),
    };
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_attempts_per_server = 1;
    let resolver = Resolver::new(transport, settings);

    let result = resolver.resolve_with_stats(query).await.unwrap();

    assert_eq!(result.response().headers.rcode, RCode::Ok);
    assert_eq!(result.stats().udp_transmissions(), 0);
    assert_eq!(*calls.lock().unwrap(), 2);
}

#[tokio::test]
async fn udp_retry_is_limited_by_the_udp_attempt_budget() {
    let query = question(&["www", "example"]);
    let attempts = Arc::new(Mutex::new(0));
    let transport = RetryTransport {
        attempts: Arc::clone(&attempts),
        reply: response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 1)],
        ),
    };
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_attempts_per_server = 1;
    let resolver = Resolver::new(transport, settings);

    assert!(matches!(
        resolver.resolve(query).await,
        Err(ResolveError::NoReachableServer)
    ));
    assert_eq!(*attempts.lock().unwrap(), 1);
}

#[tokio::test]
async fn timeout_processing_consumes_a_separate_work_unit() {
    let query = question(&["www", "example"]);
    let attempts = Arc::new(Mutex::new(0));
    let transport = RetryTransport {
        attempts: Arc::clone(&attempts),
        reply: response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 1)],
        ),
    };
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_steps = 2;
    let resolver = Resolver::new(transport, settings);

    assert!(matches!(
        resolver.resolve(query).await,
        Err(ResolveError::WorkLimitExceeded)
    ));
    assert_eq!(*attempts.lock().unwrap(), 1);
}

#[tokio::test]
async fn answers_a_single_packet_cname_chain_without_another_query() {
    // A response may carry several CNAME RRs leading toward the ultimate
    // canonical name together with its RRset (RFC 1034 §3.6.2, referenced by
    // RFC 1035 §3.3.1). The complete packet must be accepted as terminal.
    let original = question(&["www", "example"]);
    let first = name(&["origin", "example"]);
    let second = name(&["canonical", "example"]);
    let cname = |owner: DomainName, target: DomainName| ResourceRecord {
        name: owner,
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target),
    };
    let address = ResourceRecord {
        name: second.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            referral_response(name(&["example"]), name(&["ns", "example"]), 53),
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![
                    cname(original.qname.clone(), first.clone()),
                    cname(first, second.clone()),
                    address,
                ],
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let reply = resolver.resolve(original.clone()).await.unwrap();
    let repeated_alias = resolver.resolve(original).await.unwrap();
    let direct_target = resolver
        .resolve(question(&["canonical", "example"]))
        .await
        .unwrap();

    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(reply.answers.len(), 3);
    assert_eq!(repeated_alias.answers.len(), 3);
    assert_eq!(direct_target.answers.len(), 1);
    assert!(direct_target.answers[0].name.eq_dns(&second));
    assert!(reply.answers[0].name.eq_dns(&name(&["www", "example"])));
    assert!(reply.answers[1].name.eq_dns(&name(&["origin", "example"])));
    assert!(
        reply.answers[2]
            .name
            .eq_dns(&name(&["canonical", "example"]))
    );
}

#[tokio::test]
async fn preserves_every_hop_of_a_cname_chain_followed_across_packets() {
    // When a packet ends mid-chain, every CNAME RR it carried must survive in
    // the final answer, not only the hop at the original QNAME.
    let original = question(&["www", "example"]);
    let first = name(&["origin", "example"]);
    let second = name(&["canonical", "example"]);
    let cname = |owner: DomainName, target: DomainName| ResourceRecord {
        name: owner,
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target),
    };
    let address = ResourceRecord {
        name: second.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            referral_response(name(&["example"]), name(&["ns", "example"]), 53),
            response(
                Headers {
                    qr: true,
                    ..Headers::default()
                },
                vec![
                    cname(original.qname.clone(), first.clone()),
                    cname(first.clone(), second.clone()),
                ],
            ),
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![address],
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let reply = resolver.resolve(original.clone()).await.unwrap();

    assert_eq!(reply.answers.len(), 3);
    assert!(reply.answers[0].name.eq_dns(&name(&["www", "example"])));
    assert!(reply.answers[1].name.eq_dns(&first));
    assert!(reply.answers[2].name.eq_dns(&second));
    // The completed packet answers the original question, and the final answer
    // may be authoritative only for the CNAME target, not the original name.
    assert_eq!(reply.questions.len(), 1);
    assert!(reply.questions[0].qname.eq_dns(&original.qname));
    assert!(!reply.headers.aa);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].questions[0].qname.eq_dns(&second));
}

async fn assert_caches_cross_packet_cname_negative(rcode: RCode) {
    let alias = question(&["www", "example"]);
    let target = question(&["missing", "example"]);
    let cname = ResourceRecord {
        name: alias.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target.qname.clone()),
    };
    let first = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![cname],
    );
    let mut terminal = response(
        Headers {
            qr: true,
            aa: true,
            rcode,
            ..Headers::default()
        },
        Vec::new(),
    );
    terminal.authorities = vec![soa_record(name(&["example"]), 60, 30)];
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![first, terminal])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
    );

    let first = resolver.resolve(alias.clone()).await.unwrap();
    let repeated_alias = resolver.resolve(alias).await.unwrap();
    let direct_target = resolver.resolve(target.clone()).await.unwrap();

    assert_eq!(first.headers.rcode, rcode);
    assert_eq!(repeated_alias.headers.rcode, rcode);
    assert_eq!(direct_target.headers.rcode, rcode);
    assert!(
        first
            .answers
            .iter()
            .any(|record| record.rtype == RecordType::CNAME)
    );
    assert!(
        repeated_alias
            .answers
            .iter()
            .any(|record| record.rtype == RecordType::CNAME)
    );
    assert!(direct_target.answers.is_empty());
    assert_eq!(direct_target.questions.len(), 1);
    assert!(direct_target.questions[0].qname.eq_dns(&target.qname));
    assert_eq!(direct_target.questions[0].qtype, target.qtype);
    assert_eq!(direct_target.questions[0].qclass, target.qclass);
    assert!(
        direct_target
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::SOA && record.ttl <= 30)
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn caches_cross_packet_cname_nodata_for_alias_and_target_reuse() {
    assert_caches_cross_packet_cname_negative(RCode::Ok).await;
}

#[tokio::test]
async fn caches_cross_packet_cname_nxdomain_for_alias_and_target_reuse() {
    assert_caches_cross_packet_cname_negative(RCode::NameError).await;
}

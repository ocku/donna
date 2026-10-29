use super::*;

#[test]
fn matches_rfc1035_query_type_pseudo_values() {
    assert!(query_type_matches_record(QueryType::ANY, RecordType::A));
    assert!(query_type_matches_record(QueryType::MAILB, RecordType::MB));
    assert!(query_type_matches_record(QueryType::MAILB, RecordType::MG));
    assert!(query_type_matches_record(QueryType::MAILB, RecordType::MR));
    assert!(query_type_matches_record(QueryType::MAILA, RecordType::MD));
    assert!(query_type_matches_record(QueryType::MAILA, RecordType::MF));
    assert!(!query_type_matches_record(QueryType::MAILA, RecordType::MX));
    assert!(!query_type_matches_record(QueryType::MAILA, RecordType::A));
    assert!(query_type_matches_record(QueryType::CAA, RecordType::CAA));
}

#[tokio::test]
async fn preserves_reserved_caa_flags_from_an_authority_and_through_cache() {
    let mut query = question(&["www", "example"]);
    query.qtype = QueryType::CAA;
    let answer = ResourceRecord {
        name: query.qname.clone(),
        rtype: RecordType::CAA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CAA(Caa {
            flags: 0x01,
            tag: b"issue".to_vec(),
            value: b"ca.example".to_vec(),
        }),
    };
    let requests = Arc::new(Mutex::new(Vec::new()));
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![answer],
        )])),
        requests: Arc::clone(&requests),
    };
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let reply = resolver.resolve(query.clone()).await.unwrap();

    assert!(matches!(
        &reply.answers[0].rdata,
        RData::CAA(caa) if caa.flags == 0x01 && caa.has_reserved_flags()
    ));
    let first_rdata = reply.answers[0].rdata.clone();
    let forwarded = Message::from_wire(&reply.into_wire().unwrap()).unwrap();
    assert_eq!(forwarded.answers[0].rdata, first_rdata);
    let cached = resolver.resolve(query).await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(cached.answers[0].rdata, first_rdata);
    assert!(matches!(
        &cached.answers[0].rdata,
        RData::CAA(caa) if caa.flags == 0x01
    ));
}

#[tokio::test]
async fn retries_an_edns_unaware_server_without_opt() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_steps = 2;
    settings.max_attempts_per_server = 2;
    let resolver = Resolver::new(
        EdnsUnawareTransport {
            requests: Arc::clone(&requests),
            sends_opt_after_fallback: false,
        },
        settings,
    );

    let result = resolver
        .resolve_with_stats(question(&["www", "example"]))
        .await
        .unwrap();

    assert_eq!(result.response().answers.len(), 1);
    assert!(result.response().edns().unwrap().is_none());
    assert_eq!(result.stats().udp_transmissions(), 2);
    assert_eq!(result.stats().edns_fallbacks(), 1);
    assert_eq!(result.stats().server_latency_samples(), 2);
    assert_eq!(result.stats().response_rounds(), 1);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].edns().unwrap().is_some());
    assert!(requests[1].edns().unwrap().is_none());
    assert_eq!(requests[0].headers.id, requests[1].headers.id);
    assert!(
        requests[0].questions[0]
            .qname
            .eq_dns(&requests[1].questions[0].qname)
    );
}

#[tokio::test]
async fn edns_fallback_obeys_the_per_server_attempt_limit() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_steps = 2;
    settings.max_attempts_per_server = 1;
    let resolver = Resolver::new(
        EdnsUnawareTransport {
            requests: Arc::clone(&requests),
            sends_opt_after_fallback: false,
        },
        settings,
    );

    assert!(matches!(
        resolver.resolve(question(&["www", "example"])).await,
        Err(ResolveError::TemporaryServerFailure)
    ));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].edns().unwrap().is_some());
}

#[tokio::test]
async fn edns_fallback_obeys_the_resolution_work_limit() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_steps = 1;
    let resolver = Resolver::new(
        EdnsUnawareTransport {
            requests: Arc::clone(&requests),
            sends_opt_after_fallback: false,
        },
        settings,
    );

    assert!(matches!(
        resolver.resolve(question(&["www", "example"])).await,
        Err(ResolveError::WorkLimitExceeded)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn rejects_an_opt_response_to_the_unextended_fallback_request() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_attempts_per_server = 2;
    let resolver = Resolver::new(
        EdnsUnawareTransport {
            requests: Arc::clone(&requests),
            sends_opt_after_fallback: true,
        },
        settings,
    );

    assert!(matches!(
        resolver.resolve(question(&["www", "example"])).await,
        Err(ResolveError::NoReachableServer)
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn badvers_is_not_misclassified_as_nodata() {
    let query = question(&["www", "example"]);
    let mut badvers = response(
        Headers {
            qr: true,
            ..Headers::default()
        },
        Vec::new(),
    );
    badvers.additionals.push(
        dns::Edns {
            extended_rcode: 1,
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );
    let mut answer = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 1)],
    );
    answer.additionals.push(dns::Edns::new(1232).into_record());
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![badvers, answer])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(
        transport,
        config(vec![
            "192.0.2.54:53".parse().unwrap(),
            "192.0.2.53:53".parse().unwrap(),
        ]),
    );

    let reply = resolver.resolve(query).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert!(reply.edns().unwrap().is_none());
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn unsupported_edns_version_response_is_ignored_and_not_cached() {
    let query = question(&["www", "example"]);
    let mut unsupported = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 1)],
    );
    unsupported.additionals.push(
        dns::Edns {
            version: 1,
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![unsupported])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
    );

    assert!(matches!(
        resolver.resolve(query.clone()).await,
        Err(ResolveError::NoReachableServer)
    ));
    assert!(resolver.positive_cache.get_question(&query).is_none());
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn valid_edns_zero_answer_wins_after_unsupported_version_response() {
    let mut unsupported = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        Vec::new(),
    );
    unsupported.additionals.push(
        dns::Edns {
            version: 1,
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );

    assert_unusable_edns_reply_is_not_accepted_or_cached(unsupported).await;
}

async fn assert_unusable_edns_reply_is_not_accepted_or_cached(mut unusable: Message) {
    let query = question(&["www", "example"]);
    unusable
        .answers
        .insert(0, address_record(query.qname.clone(), 1));
    let mut valid = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 2)],
    );
    valid.additionals.push(dns::Edns::new(1232).into_record());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![unusable, valid])),
            requests: Arc::clone(&requests),
        },
        ResolverConfig {
            max_concurrent_queries: 2,
            ..config(vec![
                "192.0.2.54:53".parse().unwrap(),
                "192.0.2.53:53".parse().unwrap(),
            ])
        },
    );

    let reply = resolver.resolve(query.clone()).await.unwrap();
    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 2))
    );

    let cached = resolver.resolve(query).await.unwrap();
    assert_eq!(
        cached.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 2))
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

async fn assert_advisory_edns_reply_is_accepted_and_cached(options: Vec<dns::EdnsOption>) {
    let query = question(&["www", "example"]);
    let mut reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 1)],
    );
    reply.additionals.push(
        dns::Edns {
            options,
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![reply])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
    );

    let resolved = resolver.resolve(query.clone()).await.unwrap();
    assert_eq!(
        resolved.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert!(resolved.edns().unwrap().is_none());

    let cached = resolver.resolve(query).await.unwrap();
    assert_eq!(
        cached.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn accepts_and_caches_positive_response_with_non_nfc_ede_text() {
    assert_advisory_edns_reply_is_accepted_and_cached(vec![dns::EdnsOption {
        code: dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
        data: [vec![0, 0], "Cafe\u{301}".as_bytes().to_vec()].concat(),
    }])
    .await;
}

#[tokio::test]
async fn accepts_and_caches_positive_response_with_nonfinal_padding() {
    assert_advisory_edns_reply_is_accepted_and_cached(vec![
        dns::EdnsOption::padding(3),
        dns::EdnsOption {
            code: 65_000,
            data: vec![1],
        },
    ])
    .await;
}

#[tokio::test]
async fn rejects_and_does_not_cache_a_positive_response_with_multiple_opts() {
    let mut malformed = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        Vec::new(),
    );
    malformed.additionals = vec![
        dns::Edns {
            // If duplicate-OPT validation were skipped, falling back to the
            // header nibble would turn this extended error into NOERROR.
            extended_rcode: 1,
            ..dns::Edns::new(1232)
        }
        .into_record(),
        dns::Edns::new(1232).into_record(),
    ];

    assert_unusable_edns_reply_is_not_accepted_or_cached(malformed).await;
}

#[tokio::test]
async fn rejects_and_does_not_cache_a_positive_response_with_misplaced_opt() {
    let mut malformed = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        Vec::new(),
    );
    malformed
        .authorities
        .push(dns::Edns::new(1232).into_record());

    assert_unusable_edns_reply_is_not_accepted_or_cached(malformed).await;
}

#[tokio::test]
async fn rejects_and_does_not_cache_a_positive_response_with_invalid_opt_fixed_part() {
    let mut malformed = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        Vec::new(),
    );
    let mut opt = dns::Edns::new(1232).into_record();
    opt.name = name(&["not-root"]);
    malformed.additionals.push(opt);

    assert_unusable_edns_reply_is_not_accepted_or_cached(malformed).await;
}

#[tokio::test]
async fn malformed_ede_does_not_change_dns_processing_or_caching() {
    let query = question(&["www", "example"]);
    let mut reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 1)],
    );
    reply.additionals.push(
        dns::Edns {
            options: vec![dns::EdnsOption {
                code: dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
                data: vec![0],
            }],
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![reply])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
    );

    let resolved = resolver.resolve(query.clone()).await.unwrap();
    assert_eq!(
        resolved.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert!(resolved.edns().unwrap().is_none());

    let cached = resolver.resolve(query).await.unwrap();
    assert_eq!(
        cached.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn rejects_and_does_not_cache_duplicate_padding() {
    let mut malformed = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        Vec::new(),
    );
    malformed.additionals.push(
        dns::Edns {
            options: vec![dns::EdnsOption::padding(0), dns::EdnsOption::padding(1)],
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );

    assert_unusable_edns_reply_is_not_accepted_or_cached(malformed).await;
}

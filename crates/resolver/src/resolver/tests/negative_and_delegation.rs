use super::*;

fn negative_response(query: &Question, rcode: RCode, authoritative: bool) -> Message {
    let mut reply = response(
        Headers {
            qr: true,
            aa: authoritative,
            rcode,
            ..Headers::default()
        },
        Vec::new(),
    );
    reply.authorities = vec![soa_record(name(&["example"]), 60, 30)];
    reply.questions = vec![query.clone()];
    reply
}

async fn assert_non_authoritative_negative_loses_to_authoritative_answer(rcode: RCode) {
    let query = question(&["missing", "example"]);
    let answer = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 2)],
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![
                negative_response(&query, rcode, false),
                answer,
            ])),
            requests: Arc::clone(&requests),
        },
        ResolverConfig {
            max_concurrent_queries: 2,
            ..config(vec![
                "192.0.2.1:53".parse().unwrap(),
                "192.0.2.2:53".parse().unwrap(),
            ])
        },
    );

    let reply = resolver.resolve(query.clone()).await.unwrap();
    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 2))
    );

    let cached = resolver.resolve(query.clone()).await.unwrap();
    assert_eq!(
        cached.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 2))
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert!(resolver.negative_cache.get(&query).is_none());
}

#[tokio::test]
async fn non_authoritative_nxdomain_does_not_beat_an_authoritative_answer() {
    assert_non_authoritative_negative_loses_to_authoritative_answer(RCode::NameError).await;
}

#[tokio::test]
async fn non_authoritative_nodata_does_not_beat_an_authoritative_answer() {
    assert_non_authoritative_negative_loses_to_authoritative_answer(RCode::Ok).await;
}

#[tokio::test]
async fn lone_non_authoritative_negatives_are_exhausted_and_not_cached() {
    for rcode in [RCode::NameError, RCode::Ok] {
        let query = question(&["missing", "example"]);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = Resolver::new(
            MockTransport {
                replies: Arc::new(Mutex::new(vec![
                    negative_response(&query, rcode, false),
                    negative_response(&query, rcode, false),
                ])),
                requests: Arc::clone(&requests),
            },
            config(vec![
                "192.0.2.1:53".parse().unwrap(),
                "192.0.2.2:53".parse().unwrap(),
            ]),
        );

        let result = resolver.resolve(query.clone()).await;

        if rcode == RCode::NameError {
            assert!(matches!(result, Err(ResolveError::TemporaryServerFailure)));
        } else {
            assert!(matches!(result, Err(ResolveError::NoReachableServer)));
        }
        assert_eq!(requests.lock().unwrap().len(), 2);
        assert!(resolver.negative_cache.get(&query).is_none());
    }
}

#[tokio::test]
async fn does_not_follow_a_cname_from_a_failed_response() {
    let original = question(&["www", "example"]);
    let target = name(&["malicious", "example"]);
    let cname = ResourceRecord {
        name: original.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target.clone()),
    };
    let answer = ResourceRecord {
        name: original.qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            response(
                Headers {
                    qr: true,
                    rcode: RCode::ServerFailure,
                    ..Headers::default()
                },
                vec![cname],
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
        ]),
    );

    let reply = resolver.resolve(original.clone()).await.unwrap();
    assert_eq!(reply.headers.rcode, RCode::Ok);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.questions[0].qname.eq_dns(&original.qname))
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.questions[0].qname.eq_dns(&target))
    );
}

#[tokio::test]
async fn rejects_a_same_zone_cut_when_starting_from_roots() {
    let query = question(&["www", "example"]);
    let root_referral = referral_response(DomainName::root(), name(&["ns"]), 53);
    let answer = address_record(query.qname.clone(), 1);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            root_referral,
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

#[tokio::test]
async fn tries_the_next_root_after_an_unusable_glueless_referral() {
    #[derive(Clone)]
    struct GluelessReferralTransport {
        first_root: SocketAddr,
        second_root: SocketAddr,
        original: DomainName,
        name_server: DomainName,
        requests: Arc<Mutex<Vec<(SocketAddr, DomainName, QueryType)>>>,
    }

    impl Transport for GluelessReferralTransport {
        fn exchange<'future>(
            &'future self,
            server: SocketAddr,
            query: &'future Message,
            _timeout: Duration,
        ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
            Box::pin(async move {
                let question = &query.questions[0];
                self.requests.lock().unwrap().push((
                    server,
                    question.qname.clone(),
                    question.qtype,
                ));
                let mut reply = if server == self.first_root
                    && question.qname.eq_dns(&self.original)
                {
                    let mut referral =
                        referral_response(name(&["example"]), self.name_server.clone(), 53);
                    referral.additionals.clear();
                    referral
                } else if server == self.first_root && question.qname.eq_dns(&self.name_server) {
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        Vec::new(),
                    )
                } else if server == self.second_root && question.qname.eq_dns(&self.original) {
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![address_record(self.original.clone(), 1)],
                    )
                } else {
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "query sent to an unexpected server",
                    )));
                };
                reply.headers.id = query.headers.id;
                reply.questions = query.questions.clone();
                Ok(reply)
            })
        }
    }

    let first_root = "192.0.2.1:53".parse().unwrap();
    let second_root = "192.0.2.2:53".parse().unwrap();
    let query = question(&["www", "example"]);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        GluelessReferralTransport {
            first_root,
            second_root,
            original: query.qname.clone(),
            name_server: name(&["ns", "example"]),
            requests: Arc::clone(&requests),
        },
        config(vec![second_root, first_root]),
    );

    let reply = resolver.resolve(query.clone()).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].0, first_root);
    assert_eq!(requests[1].2, QueryType::A);
    assert_eq!(requests[2].2, QueryType::AAAA);
    assert_eq!(requests[3].0, second_root);
    assert!(requests[3].1.eq_dns(&query.qname));
}

#[tokio::test]
async fn restarts_from_root_after_a_cached_delegation_is_exhausted() {
    let zone = name(&["child", "example"]);
    let first = question(&["www", "child", "example"]);
    let second = question(&["api", "child", "example"]);
    let initial_referral = referral_response(zone, name(&["ns", "child", "example"]), 53);
    let ancestor_referral = referral_response(name(&["example"]), name(&["ns", "example"]), 54);
    let replies = Arc::new(Mutex::new(vec![
        initial_referral,
        response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(first.qname.clone(), 1)],
        ),
        ancestor_referral,
        response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            Vec::new(),
        ),
        response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            Vec::new(),
        ),
        response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(second.qname.clone(), 2)],
        ),
    ]));
    let transport = MockTransport {
        replies: Arc::clone(&replies),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.1:53".parse().unwrap()]));

    resolver.resolve(first).await.unwrap();
    let reply = resolver.resolve(second).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(requests.lock().unwrap().len(), 6);
    assert!(replies.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reuses_cached_delegation_for_another_name_in_the_zone() {
    let delegated_zone = name(&["example"]);
    let name_server = name(&["ns", "example"]);
    let first = question(&["www", "example"]);
    let second = question(&["api", "example"]);
    let referral = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: delegated_zone,
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 300,
            rdata: RData::NS(name_server.clone()),
        }],
        additionals: vec![ResourceRecord {
            name: name_server,
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        }],
    };
    let first_answer = ResourceRecord {
        name: first.qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let second_answer = ResourceRecord {
        name: second.qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
    };
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            referral,
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![first_answer],
            ),
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![second_answer],
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.1:53".parse().unwrap()]));

    resolver.resolve(first).await.unwrap();
    let second_result = resolver.resolve_with_stats(second.clone()).await.unwrap();

    assert_eq!(
        second_result.stats().final_cache_source(),
        Some(ResolutionCacheSource::Delegation)
    );
    assert_eq!(second_result.stats().udp_transmissions(), 1);
    assert_eq!(second_result.stats().response_rounds(), 1);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        3,
        "the second lookup should skip the root server"
    );
    assert!(requests[2].questions[0].qname.eq_dns(&second.qname));
}

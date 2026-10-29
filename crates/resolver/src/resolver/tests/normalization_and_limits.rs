use super::*;

#[tokio::test]
async fn cross_packet_authoritative_target_resists_non_authoritative_replacement() {
    let alias = question(&["www", "example"]);
    let other_alias = question(&["other", "example"]);
    let target = question(&["origin", "example"]);
    let cname = |owner: DomainName| ResourceRecord {
        name: owner,
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
        vec![cname(alias.qname.clone())],
    );
    let authoritative_target = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(target.qname.clone(), 1)],
    );
    let non_authoritative_conflict = response(
        Headers {
            qr: true,
            ..Headers::default()
        },
        vec![
            cname(other_alias.qname.clone()),
            address_record(target.qname.clone(), 2),
        ],
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![
                first,
                authoritative_target,
                non_authoritative_conflict,
            ])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
    );

    resolver.resolve(alias).await.unwrap();
    let conflicting = resolver.resolve(other_alias).await.unwrap();
    let cached_target = resolver.resolve(target).await.unwrap();

    assert!(
        conflicting
            .answers
            .iter()
            .any(|record| { record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 1)) })
    );
    assert_eq!(cached_target.answers.len(), 1);
    assert_eq!(
        cached_target.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn normalizes_authoritative_rrsets_after_a_cross_packet_cname_restart() {
    let original = question(&["www", "example"]);
    let canonical = name(&["canonical", "example"]);
    let alias = ResourceRecord {
        name: original.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(canonical.clone()),
    };
    let mut first = address_record(canonical.clone(), 1);
    let mut second = address_record(canonical.clone(), 2);
    first.ttl = 60;
    second.ttl = 30;
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![alias],
            ),
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![first, second],
            ),
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let reply = resolver.resolve(original).await.unwrap();

    let canonical_answers = reply
        .answers
        .iter()
        .filter(|record| record.name.eq_dns(&canonical) && record.rtype == RecordType::A)
        .collect::<Vec<_>>();
    assert_eq!(canonical_answers.len(), 2);
    // The two records normalize to the smaller upstream TTL. Processing and
    // scheduling may then age that TTL before the composed answer is sent.
    let normalized_ttl = canonical_answers[0].ttl;
    assert!((1..=30).contains(&normalized_ttl));
    assert!(
        canonical_answers
            .iter()
            .all(|record| record.ttl == normalized_ttl)
    );
}

#[tokio::test]
async fn accepts_type_one_nodata_instead_of_following_its_ns_records() {
    let query = question(&["www", "example"]);
    let mut nodata = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        Vec::new(),
    );
    nodata.authorities = vec![
        soa_record(name(&["example"]), 60, 30),
        ResourceRecord {
            name: name(&["example"]),
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::NS(name(&["ns", "example"])),
        },
    ];
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            referral_response(name(&["example"]), name(&["ns", "example"]), 53),
            nodata,
        ])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.1:53".parse().unwrap()]));

    let reply = resolver.resolve(query.clone()).await.unwrap();
    let cached = resolver.resolve(query).await.unwrap();

    assert_eq!(reply.headers.rcode, RCode::Ok);
    assert!(reply.answers.is_empty());
    assert_eq!(reply.authorities.len(), 2);
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert!(
        cached
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NS)
    );
}

#[tokio::test]
async fn ignores_a_non_authoritative_mixed_ttl_rrset_and_tries_another_server() {
    let query = question(&["www", "example"]);
    let mut first = address_record(query.qname.clone(), 1);
    first.ttl = 60;
    let mut second = address_record(query.qname.clone(), 2);
    second.ttl = 30;
    let good = address_record(query.qname.clone(), 3);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![
            response(
                Headers {
                    qr: true,
                    ..Headers::default()
                },
                vec![first, second],
            ),
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![good],
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
    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 3))
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn tries_another_server_after_malformed_cname_data() {
    let query = question(&["www", "example"]);
    let cname = |target: DomainName| ResourceRecord {
        name: query.qname.clone(),
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
                    aa: true,
                    ..Headers::default()
                },
                vec![
                    cname(name(&["first", "example"])),
                    cname(name(&["second", "example"])),
                ],
            ),
            response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![address_record(query.qname.clone(), 9)],
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
async fn resolves_a_glued_name_server_again_after_its_glue_fails() {
    #[derive(Clone)]
    struct PartialGlueTransport {
        root: SocketAddr,
        dead_glue: SocketAddr,
        resolved: SocketAddr,
        original: DomainName,
        second: DomainName,
        name_server: DomainName,
        requests: Arc<Mutex<Vec<(SocketAddr, DomainName)>>>,
    }

    impl Transport for PartialGlueTransport {
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
                let qname = query.questions[0].qname.clone();
                self.requests.lock().unwrap().push((server, qname.clone()));
                if server == self.dead_glue {
                    return Err(TransportError::Timeout);
                }
                let mut reply = if server == self.root && qname.eq_dns(&self.original) {
                    Message {
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
                            rdata: RData::NS(self.name_server.clone()),
                        }],
                        additionals: vec![address_record(self.name_server.clone(), 2)],
                    }
                } else if server == self.root && qname.eq_dns(&self.name_server) {
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![address_record(self.name_server.clone(), 3)],
                    )
                } else if server == self.resolved
                    && (qname.eq_dns(&self.original) || qname.eq_dns(&self.second))
                {
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![address_record(qname.clone(), 9)],
                    )
                } else {
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "unexpected route",
                    )));
                };
                reply.headers.id = query.headers.id;
                reply.questions = query.questions.clone();
                Ok(reply)
            })
        }
    }

    let root = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let dead_glue = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53));
    let resolved = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 3), 53));
    let original = name(&["www", "example"]);
    let second = name(&["api", "example"]);
    let name_server = name(&["ns1", "example"]);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(vec![root]);
    settings.max_steps = 16;
    settings.max_attempts_per_server = 1;
    let resolver = Resolver::new(
        PartialGlueTransport {
            root,
            dead_glue,
            resolved,
            original: original.clone(),
            second: second.clone(),
            name_server: name_server.clone(),
            requests: Arc::clone(&requests),
        },
        settings,
    );

    let reply = resolver
        .resolve(question(&["www", "example"]))
        .await
        .unwrap();
    let reused = resolver
        .resolve(question(&["api", "example"]))
        .await
        .unwrap();

    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 9))
    );
    assert_eq!(
        reused.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 9))
    );
    let requests = requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|(server, qname)| { *server == root && qname.eq_dns(&name_server) })
    );
    assert!(
        requests
            .iter()
            .any(|(server, qname)| { *server == dead_glue && qname.eq_dns(&original) })
    );
    assert!(
        requests
            .iter()
            .any(|(server, qname)| { *server == dead_glue && qname.eq_dns(&second) })
    );
    assert!(
        requests
            .iter()
            .any(|(server, qname)| { *server == resolved && qname.eq_dns(&original) })
    );
    assert!(
        requests
            .iter()
            .any(|(server, qname)| { *server == resolved && qname.eq_dns(&second) })
    );
}

#[tokio::test]
async fn tcp_fallback_consumes_a_second_transmission_unit() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(vec!["192.0.2.53:53".parse().unwrap()]);
    settings.max_steps = 1;
    let resolver = Resolver::new(truncation_route(Arc::clone(&calls), false), settings);

    assert!(matches!(
        resolver.resolve(question(&["www", "example"])).await,
        Err(ResolveError::WorkLimitExceeded)
    ));
    assert_eq!(*calls.lock().unwrap(), ["udp"]);
}

#[tokio::test]
async fn deduplicates_server_addresses_and_honors_the_attempt_limit() {
    let query = question(&["www", "example"]);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 1)],
        )])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let server = "192.0.2.53:53".parse().unwrap();
    let mut settings = config(vec![server, server, server]);
    settings.max_attempts_per_server = 1;
    let resolver = Resolver::new(transport, settings);

    resolver.resolve(query).await.unwrap();

    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn uses_the_configured_query_id_source() {
    fn fixed_id() -> u16 {
        0xa5a5
    }

    let query = question(&["www", "example"]);
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 1)],
        )])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new_with_id_source(
        transport,
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        fixed_id,
    );

    resolver.resolve(query).await.unwrap();

    assert_eq!(requests.lock().unwrap()[0].headers.id, 0xa5a5);
}

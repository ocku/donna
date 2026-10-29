use super::*;

#[tokio::test(start_paused = true)]
async fn suspended_a_is_resumed_after_aaaa_target_failure_without_retransmission() {
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
        additionals: Vec::new(),
    };
    let ipv4_address = address_record(name_server.clone(), 54);
    let ipv6_address = ResourceRecord {
        name: name_server.clone(),
        rtype: RecordType::AAAA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::AAAA(Ipv6Addr::LOCALHOST),
    };
    let answer = ResourceRecord {
        name: query.qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    #[derive(Clone)]
    struct DualStackTransport {
        root: SocketAddr,
        delegated_ipv4: SocketAddr,
        delegated_ipv6: SocketAddr,
        original: DomainName,
        name_server: DomainName,
        referral: Message,
        ipv4_address: ResourceRecord,
        ipv6_address: ResourceRecord,
        answer: ResourceRecord,
        requests: Arc<Mutex<Vec<(SocketAddr, QueryType)>>>,
    }

    impl Transport for DualStackTransport {
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
                let question = &query.questions[0];
                self.requests.lock().unwrap().push((server, question.qtype));
                let mut reply = if question.qname.eq_dns(&self.name_server) {
                    assert_eq!(server, self.root);
                    let address = if question.qtype == QueryType::A {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        self.ipv4_address.clone()
                    } else {
                        assert_eq!(question.qtype, QueryType::AAAA);
                        self.ipv6_address.clone()
                    };
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![address],
                    )
                } else {
                    assert!(question.qname.eq_dns(&self.original));
                    if server == self.root {
                        self.referral.clone()
                    } else if server == self.delegated_ipv6 {
                        return Err(TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "IPv6 name server unavailable",
                        )));
                    } else {
                        assert_eq!(server, self.delegated_ipv4);
                        response(
                            Headers {
                                qr: true,
                                aa: true,
                                ..Headers::default()
                            },
                            vec![self.answer.clone()],
                        )
                    }
                };
                reply.headers.id = query.headers.id;
                reply.questions = query.questions.clone();
                Ok(reply)
            })
        }
    }

    let root = "192.0.2.53:53".parse().unwrap();
    let delegated_ipv4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 54), 53));
    let delegated_ipv6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 53));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let transport = DualStackTransport {
        root,
        delegated_ipv4,
        delegated_ipv6,
        original: query.qname.clone(),
        name_server,
        referral,
        ipv4_address,
        ipv6_address,
        answer,
        requests: Arc::clone(&requests),
    };
    let mut settings = config(vec![root]);
    settings.max_concurrent_queries = 2;
    let resolver = Resolver::new(transport, settings);

    let result = resolver.resolve_with_stats(query).await.unwrap();

    assert_eq!(result.response().answers.len(), 1);
    assert_eq!(result.stats().name_server_lookups(), 2);
    assert_eq!(
        result.stats().udp_transmissions(),
        6,
        "requests={:?}",
        requests.lock().unwrap()
    );
    assert_eq!(result.stats().canceled_name_server_family_lookups(), 0);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[1], (root, QueryType::A));
    assert_eq!(requests[2], (root, QueryType::AAAA));
    assert!(
        requests[3..5]
            .iter()
            .all(|request| *request == (delegated_ipv6, QueryType::A))
    );
    assert_eq!(requests[5], (delegated_ipv4, QueryType::A));
    assert_eq!(
        requests[1..]
            .iter()
            .filter(|request| **request == (root, QueryType::A))
            .count(),
        1
    );
}
#[tokio::test]
async fn resolves_a_glueless_name_server_address_through_a_cname_chain() {
    #[derive(Clone)]
    struct RoutedTransport {
        root_server: SocketAddr,
        canonical_server: SocketAddr,
        query_name: DomainName,
        name_server: DomainName,
        first_target: DomainName,
        canonical_name: DomainName,
        referral: Message,
        address_reply: Message,
        first_target_reply: Message,
        canonical_address_reply: Message,
        answer_reply: Message,
        requests: Arc<Mutex<Vec<(SocketAddr, Message)>>>,
    }

    impl Transport for RoutedTransport {
        fn exchange<'future>(
            &'future self,
            server: SocketAddr,
            query: &'future Message,
            _timeout: Duration,
        ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push((server, query.clone()));
                let qname = &query.questions[0].qname;
                let mut reply = if server == self.root_server && qname.eq_dns(&self.query_name) {
                    self.referral.clone()
                } else if server == self.root_server && qname.eq_dns(&self.name_server) {
                    if query.questions[0].qtype == QueryType::A {
                        self.address_reply.clone()
                    } else {
                        response(
                            Headers {
                                qr: true,
                                aa: true,
                                ..Headers::default()
                            },
                            Vec::new(),
                        )
                    }
                } else if server == self.root_server && qname.eq_dns(&self.canonical_name) {
                    if query.questions[0].qtype == QueryType::A {
                        self.canonical_address_reply.clone()
                    } else {
                        response(
                            Headers {
                                qr: true,
                                aa: true,
                                ..Headers::default()
                            },
                            Vec::new(),
                        )
                    }
                } else if server == self.root_server && qname.eq_dns(&self.first_target) {
                    if query.questions[0].qtype == QueryType::A {
                        self.first_target_reply.clone()
                    } else {
                        response(
                            Headers {
                                qr: true,
                                aa: true,
                                ..Headers::default()
                            },
                            Vec::new(),
                        )
                    }
                } else if server == self.root_server && query.questions[0].qtype == QueryType::AAAA
                {
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        Vec::new(),
                    )
                } else if server == self.canonical_server && qname.eq_dns(&self.query_name) {
                    self.answer_reply.clone()
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

    let query = question(&["www", "example"]);
    let name_server = name(&["ns", "example"]);
    let first_target = name(&["ns-alias", "provider"]);
    let canonical_target = name(&["canonical-ns", "provider"]);
    let root_server = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let canonical_server = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let cname = |owner: DomainName, target: DomainName| ResourceRecord {
        name: owner,
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target),
    };
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
        additionals: Vec::new(),
    };
    let address_reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![cname(name_server.clone(), first_target.clone())],
    );
    let first_target_reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![cname(first_target.clone(), canonical_target.clone())],
    );
    let answer_reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 9)],
    );
    let canonical_address_reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(canonical_target.clone(), 53)],
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        RoutedTransport {
            root_server,
            canonical_server,
            query_name: query.qname.clone(),
            name_server: name_server.clone(),
            first_target: first_target.clone(),
            canonical_name: canonical_target,
            referral,
            address_reply,
            first_target_reply,
            canonical_address_reply,
            answer_reply,
            requests: Arc::clone(&requests),
        },
        ResolverConfig {
            max_steps: 16,
            ..config(vec![root_server])
        },
    );

    let reply = resolver.resolve(query.clone()).await.unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 9))
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0].0, root_server);
    assert!(requests[0].1.questions[0].qname.eq_dns(&query.qname));
    assert_eq!(requests[1].0, root_server);
    assert!(requests[1].1.questions[0].qname.eq_dns(&name_server));
    assert_eq!(requests[1].1.questions[0].qtype, QueryType::A);
    assert_eq!(requests[2].0, root_server);
    assert!(requests[2].1.questions[0].qname.eq_dns(&first_target));
    assert!(
        requests[3].1.questions[0]
            .qname
            .eq_dns(&name(&["canonical-ns", "provider"]))
    );
    assert_eq!(requests[4].0, canonical_server);
    assert!(requests[4].1.questions[0].qname.eq_dns(&query.qname));
}

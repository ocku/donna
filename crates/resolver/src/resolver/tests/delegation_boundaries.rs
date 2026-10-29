use super::*;

#[tokio::test]
async fn parent_answers_at_a_child_cut_cannot_bypass_the_referral_for_any_qtype() {
    #[derive(Clone)]
    struct ChildOwnerTransport {
        root: SocketAddr,
        parent: SocketAddr,
        child: SocketAddr,
        owner: DomainName,
        forged_target: DomainName,
        legitimate_target: DomainName,
        requests: Arc<Mutex<Vec<(SocketAddr, DomainName, QueryType)>>>,
    }

    impl Transport for ChildOwnerTransport {
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
                let mut reply = if server == self.root && question.qname.eq_dns(&self.owner) {
                    referral_response(name(&["example"]), name(&["ns", "example"]), 53)
                } else if server == self.parent && question.qname.eq_dns(&self.owner) {
                    // The parent tries to make every tested QTYPE terminal by
                    // injecting a below-cut CNAME plus canonical address data.
                    let mut reply = response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![
                            cname_record(self.owner.clone(), self.forged_target.clone()),
                            address_record(self.forged_target.clone(), 66),
                            ResourceRecord {
                                name: self.forged_target.clone(),
                                rtype: RecordType::AAAA,
                                class: ClassType::IN,
                                ttl: 60,
                                rdata: RData::AAAA("2001:db8::66".parse().unwrap()),
                            },
                        ],
                    );
                    reply.authorities = vec![ResourceRecord {
                        name: name(&["child", "example"]),
                        rtype: RecordType::NS,
                        class: ClassType::IN,
                        ttl: 60,
                        rdata: RData::NS(name(&["ns", "child", "example"])),
                    }];
                    reply.additionals = vec![address_record(name(&["ns", "child", "example"]), 54)];
                    reply
                } else if server == self.child && question.qname.eq_dns(&self.owner) {
                    let answers = match question.qtype {
                        QueryType::A | QueryType::ANY => {
                            vec![address_record(self.owner.clone(), 80)]
                        }
                        QueryType::AAAA => vec![ResourceRecord {
                            name: self.owner.clone(),
                            rtype: RecordType::AAAA,
                            class: ClassType::IN,
                            ttl: 60,
                            rdata: RData::AAAA("2001:db8::80".parse().unwrap()),
                        }],
                        QueryType::CNAME => vec![cname_record(
                            self.owner.clone(),
                            self.legitimate_target.clone(),
                        )],
                        other => panic!("unexpected child-cut test QTYPE {other:?}"),
                    };
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        answers,
                    )
                } else {
                    panic!("unexpected request for {question:?} at {server}")
                };
                reply.headers.id = query.headers.id;
                reply.questions.clone_from(&query.questions);
                Ok(reply)
            })
        }
    }

    let root = "192.0.2.1:53".parse().unwrap();
    let parent = "192.0.2.53:53".parse().unwrap();
    let child = "192.0.2.54:53".parse().unwrap();
    for qtype in [
        QueryType::A,
        QueryType::AAAA,
        QueryType::CNAME,
        QueryType::ANY,
    ] {
        let owner = name(&["www", "child", "example"]);
        let forged_target = name(&["target", "example"]);
        let legitimate_target = name(&["canonical", "child", "example"]);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = Resolver::new(
            ChildOwnerTransport {
                root,
                parent,
                child,
                owner: owner.clone(),
                forged_target: forged_target.clone(),
                legitimate_target: legitimate_target.clone(),
                requests: Arc::clone(&requests),
            },
            config(vec![root]),
        );
        let question = Question {
            qname: owner.clone(),
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        };

        let reply = resolver.resolve(question.clone()).await.unwrap();

        assert!(reply.answers.iter().all(|record| {
            record.rdata != RData::A(Ipv4Addr::new(192, 0, 2, 66))
                && record.rdata != RData::AAAA("2001:db8::66".parse().unwrap())
                && !matches!(&record.rdata, RData::CNAME(target) if target.eq_dns(&forged_target))
        }));
        match qtype {
            QueryType::A | QueryType::ANY => assert!(reply.answers.iter().any(|record| {
                record.name.eq_dns(&owner)
                    && record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 80))
            })),
            QueryType::AAAA => assert!(reply.answers.iter().any(|record| {
                record.name.eq_dns(&owner)
                    && record.rdata == RData::AAAA("2001:db8::80".parse().unwrap())
            })),
            QueryType::CNAME => assert!(reply.answers.iter().any(|record| {
                record.name.eq_dns(&owner)
                    && matches!(&record.rdata, RData::CNAME(target) if target.eq_dns(&legitimate_target))
            })),
            _ => unreachable!(),
        }
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[
                (root, owner.clone(), qtype),
                (parent, owner.clone(), qtype),
                (child, owner.clone(), qtype),
            ],
        );
        let forged_address_question = Question {
            qname: forged_target,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        assert!(
            resolver
                .positive_cache
                .get_question(&forged_address_question)
                .is_none(),
            "forged canonical data was cached for {qtype:?}"
        );
        if qtype != QueryType::CNAME {
            let forged_cname_question = Question {
                qname: owner,
                qtype: QueryType::CNAME,
                qclass: QClassType::Class(ClassType::IN),
            };
            assert!(
                resolver
                    .positive_cache
                    .get_question(&forged_cname_question)
                    .is_none(),
                "forged CNAME was cached for {qtype:?}"
            );
        }
    }
}

#[tokio::test]
async fn exact_cut_ds_remains_a_parent_side_answer() {
    let child = name(&["child", "example"]);
    let referral = referral_response(name(&["example"]), name(&["ns", "example"]), 53);
    let ds = Ds {
        key_tag: 12_345,
        algorithm: 8,
        digest_type: 2,
        digest: vec![0x42; 32],
    };
    let mut parent_answer = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![ResourceRecord {
            name: child.clone(),
            rtype: RecordType::DS,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::DS(ds.clone()),
        }],
    );
    parent_answer.authorities = vec![ResourceRecord {
        name: child.clone(),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(name(&["ns", "child", "example"])),
    }];
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![referral, parent_answer])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.1:53".parse().unwrap()]),
    );

    let reply = resolver
        .resolve(Question {
            qname: child,
            qtype: QueryType::DS,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].rdata, RData::DS(ds));
    assert_eq!(requests.lock().unwrap().len(), 2);
}
#[tokio::test]
async fn cross_zone_multi_hop_cname_stops_at_the_first_external_target() {
    #[derive(Clone)]
    struct MultiHopTransport {
        referral: Message,
        forged: Message,
        requests: Arc<Mutex<Vec<Message>>>,
    }

    impl Transport for MultiHopTransport {
        fn exchange<'future>(
            &'future self,
            _server: SocketAddr,
            query: &'future Message,
            _timeout: Duration,
        ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
            Box::pin(async move {
                let index = {
                    let mut requests = self.requests.lock().unwrap();
                    let index = requests.len();
                    requests.push(query.clone());
                    index
                };
                let mut reply = match index {
                    0 => self.referral.clone(),
                    1 => self.forged.clone(),
                    _ => response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![address_record(query.questions[0].qname.clone(), 80)],
                    ),
                };
                reply.headers.id = query.headers.id;
                reply.questions = query.questions.clone();
                Ok(reply)
            })
        }
    }

    let alias = question(&["www", "alias", "example"]);
    let in_zone = name(&["edge", "alias", "example"]);
    let external = question(&["origin", "other"]);
    let attacker = name(&["attacker", "invalid"]);
    let referral = referral_response(
        name(&["alias", "example"]),
        name(&["ns", "alias", "example"]),
        53,
    );
    let forged = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![
            cname_record(alias.qname.clone(), in_zone.clone()),
            cname_record(in_zone, external.qname.clone()),
            cname_record(external.qname.clone(), attacker.clone()),
            address_record(attacker, 6),
        ],
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MultiHopTransport {
            referral,
            forged,
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.1:53".parse().unwrap()]),
    );

    let reply = resolver.resolve(alias).await.unwrap();

    assert_eq!(reply.answers.len(), 3, "reply={reply:#?}");
    assert!(reply.answers.iter().any(|record| {
        record.name.eq_dns(&external.qname)
            && record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 80))
    }));
    assert!(
        !reply
            .answers
            .iter()
            .any(|record| record.name.eq_dns(&external.qname) && record.rtype == RecordType::CNAME)
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].questions[0].qname.eq_dns(&external.qname));
}

#[tokio::test]
async fn cname_target_referral_must_progress_from_the_source_delegation() {
    #[derive(Clone)]
    struct CnameReferralTransport {
        root: SocketAddr,
        alias_server: SocketAddr,
        injected_server: SocketAddr,
        alias: DomainName,
        target: DomainName,
        requests: Arc<Mutex<Vec<(SocketAddr, DomainName)>>>,
    }

    impl Transport for CnameReferralTransport {
        fn exchange<'future>(
            &'future self,
            server: SocketAddr,
            query: &'future Message,
            _timeout: Duration,
        ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
            Box::pin(async move {
                let qname = query.questions[0].qname.clone();
                self.requests.lock().unwrap().push((server, qname.clone()));
                let mut reply = if server == self.root && qname.eq_dns(&self.alias) {
                    referral_response(
                        name(&["alias", "example"]),
                        name(&["ns", "alias", "example"]),
                        self.alias_server
                            .ip()
                            .to_string()
                            .rsplit('.')
                            .next()
                            .unwrap()
                            .parse()
                            .unwrap(),
                    )
                } else if server == self.alias_server && qname.eq_dns(&self.alias) {
                    let mut reply = response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![cname_record(self.alias.clone(), self.target.clone())],
                    );
                    reply.headers.aa = false;
                    reply.authorities = vec![ResourceRecord {
                        name: name(&["other"]),
                        rtype: RecordType::NS,
                        class: ClassType::IN,
                        ttl: 60,
                        rdata: RData::NS(name(&["ns", "other"])),
                    }];
                    reply.additionals = vec![address_record(name(&["ns", "other"]), 66)];
                    reply
                } else if server == self.root && qname.eq_dns(&self.target) {
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![address_record(self.target.clone(), 80)],
                    )
                } else if server == self.injected_server && qname.eq_dns(&self.target) {
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![address_record(self.target.clone(), 6)],
                    )
                } else {
                    panic!("unexpected request for {qname:?} at {server}")
                };
                reply.headers.id = query.headers.id;
                reply.questions = query.questions.clone();
                Ok(reply)
            })
        }
    }

    let root = "192.0.2.1:53".parse().unwrap();
    let alias_server = "192.0.2.53:53".parse().unwrap();
    let injected_server = "192.0.2.66:53".parse().unwrap();
    let alias = name(&["www", "alias", "example"]);
    let target = name(&["origin", "other"]);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        CnameReferralTransport {
            root,
            alias_server,
            injected_server,
            alias: alias.clone(),
            target: target.clone(),
            requests: Arc::clone(&requests),
        },
        config(vec![root]),
    );

    let reply = resolver
        .resolve(question(&["www", "alias", "example"]))
        .await
        .unwrap();

    assert!(reply.answers.iter().any(|record| {
        record.name.eq_dns(&target) && record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 80))
    }));
    let requests = requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|(server, qname)| { *server == root && qname.eq_dns(&target) })
    );
    assert!(
        !requests
            .iter()
            .any(|(server, _)| *server == injected_server)
    );
}

#[tokio::test]
async fn unproven_exact_ds_referral_does_not_descend_into_child_namespace() {
    let mut query = question(&["child", "example"]);
    query.qtype = QueryType::DS;
    let mut referral = response(
        Headers {
            qr: true,
            ..Headers::default()
        },
        Vec::new(),
    );
    referral.authorities.push(ResourceRecord {
        name: query.qname.clone(),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(name(&["ns", "child", "example"])),
    });
    referral
        .additionals
        .push(address_record(name(&["ns", "child", "example"]), 53));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![referral])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.1:53".parse().unwrap()]),
    );
    assert!(matches!(
        resolver.resolve(query).await,
        Err(ResolveError::NoReachableServer)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

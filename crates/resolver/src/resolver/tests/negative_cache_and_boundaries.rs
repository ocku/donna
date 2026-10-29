use super::*;

#[tokio::test]
async fn caches_nxdomain_with_soa_across_query_types() {
    let query = question(&["missing", "example"]);
    let mut name_error = response(
        Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        Vec::new(),
    );
    name_error.authorities = vec![soa_record(name(&["example"]), 60, 30)];
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![name_error])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let first = resolver.resolve(query.clone()).await.unwrap();
    let mut other_type = query;
    other_type.qtype = QueryType::TXT;
    let second = resolver
        .resolve_with_stats(other_type.clone())
        .await
        .unwrap();

    assert_eq!(first.headers.rcode, RCode::NameError);
    assert_eq!(second.response().headers.rcode, RCode::NameError);
    assert_eq!(second.response().questions.len(), 1);
    assert!(
        second.response().questions[0]
            .qname
            .eq_dns(&other_type.qname)
    );
    assert_eq!(second.response().questions[0].qtype, other_type.qtype);
    assert_eq!(second.response().questions[0].qclass, other_type.qclass);
    assert_eq!(second.response().authorities.len(), 1);
    assert!(second.response().authorities[0].ttl <= 30);
    assert_eq!(
        second.stats().final_cache_source(),
        Some(ResolutionCacheSource::Negative)
    );
    assert_eq!(second.stats().udp_transmissions(), 0);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cached_negative_answers_include_the_learned_implicit_referral() {
    let query = question(&["missing", "example"]);
    let zone = name(&["example"]);
    let name_server = name(&["ns", "example"]);
    let referral = referral_response(zone.clone(), name_server.clone(), 53);
    let mut name_error = response(
        Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        Vec::new(),
    );
    // The authority deliberately sends RFC 2308's recommended Type 2 shape.
    name_error.authorities = vec![soa_record(zone.clone(), 60, 30)];
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![referral, name_error])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.1:53".parse().unwrap()]));

    let first = resolver.resolve(query.clone()).await.unwrap();
    let cached = resolver.resolve(query).await.unwrap();

    assert_eq!(first.headers.rcode, RCode::NameError);
    assert_eq!(cached.headers.rcode, RCode::NameError);
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert!(cached.authorities.iter().any(|record| {
        record.name.eq_dns(&zone)
            && record.rtype == RecordType::NS
            && record.ttl <= 60
            && matches!(&record.rdata, RData::NS(target) if target.eq_dns(&name_server))
    }));
}

#[tokio::test]
async fn caches_soa_backed_nodata_for_the_final_cname_target() {
    let original = question(&["www", "example"]);
    let target = question(&["missing", "example"]);
    let referral = referral_response(name(&["example"]), name(&["ns", "example"]), 53);
    let mut nodata = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![ResourceRecord {
            name: original.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CNAME(target.qname.clone()),
        }],
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
        replies: Arc::new(Mutex::new(vec![referral, nodata])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.1:53".parse().unwrap()]));

    let first = resolver.resolve(original.clone()).await.unwrap();
    let repeated_alias = resolver.resolve(original).await.unwrap();
    let cached = resolver.resolve(target.clone()).await.unwrap();

    assert_eq!(first.answers.len(), 1);
    assert_eq!(first.answers[0].rtype, RecordType::CNAME);
    assert_eq!(repeated_alias.headers.rcode, RCode::Ok);
    assert_eq!(repeated_alias.answers.len(), 1);
    assert_eq!(repeated_alias.answers[0].rtype, RecordType::CNAME);
    assert!(
        repeated_alias.answers[0]
            .name
            .eq_dns(&name(&["www", "example"]))
    );
    assert!(
        repeated_alias
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NS)
    );
    assert_eq!(cached.headers.rcode, RCode::Ok);
    assert!(cached.answers.is_empty());
    assert_eq!(cached.questions.len(), 1);
    assert!(cached.questions[0].qname.eq_dns(&target.qname));
    assert_eq!(cached.questions[0].qtype, target.qtype);
    assert_eq!(cached.questions[0].qclass, target.qclass);
    assert!(
        cached
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NS)
    );
    assert!(
        cached
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::SOA && record.ttl <= 30)
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}

async fn assert_cross_zone_cname_negative_is_ignored(rcode: RCode) {
    let alias = question(&["www", "alias", "example"]);
    let target = question(&["missing", "other"]);
    let referral = referral_response(
        name(&["alias", "example"]),
        name(&["ns", "alias", "example"]),
        53,
    );
    let mut forged = response(
        Headers {
            qr: true,
            aa: true,
            rcode,
            ..Headers::default()
        },
        vec![ResourceRecord {
            name: alias.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CNAME(target.qname.clone()),
        }],
    );
    forged.authorities = vec![soa_record(name(&["other"]), 60, 30)];
    let legitimate = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(target.qname.clone(), 80)],
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![referral, forged, legitimate])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.1:53".parse().unwrap()]),
    );

    assert!(resolver.negative_cache.get(&target).is_none());
    let reply = resolver.resolve(alias.clone()).await.unwrap();

    assert_eq!(reply.headers.rcode, RCode::Ok);
    assert!(
        reply.answers.iter().any(|record| {
            record.name.eq_dns(&alias.qname) && record.rtype == RecordType::CNAME
        })
    );
    assert!(reply.answers.iter().any(|record| {
        record.name.eq_dns(&target.qname) && record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 80))
    }));
    assert!(resolver.negative_cache.get(&target).is_none());
    let cached_target = resolver.resolve(target.clone()).await.unwrap();
    assert_eq!(
        cached_target.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 80))
    );
    let cached_alias = resolver.resolve(alias).await.unwrap();
    assert!(cached_alias.answers.iter().any(|record| {
        record.name.eq_dns(&target.qname) && record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 80))
    }));
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn empty_cache_cross_zone_cname_nxdomain_is_ignored() {
    assert_cross_zone_cname_negative_is_ignored(RCode::NameError).await;
}

#[tokio::test]
async fn empty_cache_cross_zone_cname_nodata_is_ignored() {
    assert_cross_zone_cname_negative_is_ignored(RCode::Ok).await;
}

#[tokio::test]
async fn cross_zone_cname_target_answer_is_resolved_before_it_is_cached() {
    let alias = question(&["www", "alias", "example"]);
    let target = question(&["origin", "other"]);
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
            ResourceRecord {
                name: alias.qname.clone(),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::CNAME(target.qname.clone()),
            },
            address_record(target.qname.clone(), 6),
        ],
    );
    let legitimate = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(target.qname.clone(), 80)],
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![referral, forged, legitimate])),
            requests: Arc::clone(&requests),
        },
        config(vec!["192.0.2.1:53".parse().unwrap()]),
    );

    let resolved_alias = resolver.resolve(alias).await.unwrap();
    let cached_target = resolver.resolve(target).await.unwrap();

    assert!(
        resolved_alias
            .answers
            .iter()
            .any(|record| { record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 80)) })
    );
    assert_eq!(
        cached_target.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 80))
    );
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn parent_cname_cannot_supply_canonical_data_below_a_child_delegation() {
    #[derive(Clone)]
    struct ChildCutTransport {
        root: SocketAddr,
        parent: SocketAddr,
        child: SocketAddr,
        alias: DomainName,
        target: DomainName,
        requests: Arc<Mutex<Vec<(SocketAddr, DomainName)>>>,
    }

    impl Transport for ChildCutTransport {
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
                        name(&["example"]),
                        name(&["ns", "example"]),
                        self.parent
                            .ip()
                            .to_string()
                            .rsplit('.')
                            .next()
                            .unwrap()
                            .parse()
                            .unwrap(),
                    )
                } else if server == self.parent && qname.eq_dns(&self.alias) {
                    let mut reply = response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![
                            cname_record(self.alias.clone(), self.target.clone()),
                            address_record(self.target.clone(), 66),
                        ],
                    );
                    reply.authorities = vec![ResourceRecord {
                        name: name(&["child", "example"]),
                        rtype: RecordType::NS,
                        class: ClassType::IN,
                        ttl: 60,
                        rdata: RData::NS(name(&["ns", "child", "example"])),
                    }];
                    reply.additionals = vec![address_record(
                        name(&["ns", "child", "example"]),
                        self.child
                            .ip()
                            .to_string()
                            .rsplit('.')
                            .next()
                            .unwrap()
                            .parse()
                            .unwrap(),
                    )];
                    reply
                } else if server == self.child && qname.eq_dns(&self.target) {
                    response(
                        Headers {
                            qr: true,
                            aa: true,
                            ..Headers::default()
                        },
                        vec![address_record(self.target.clone(), 80)],
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
    let parent = "192.0.2.53:53".parse().unwrap();
    let child = "192.0.2.54:53".parse().unwrap();
    let alias = name(&["alias", "example"]);
    let target = name(&["target", "child", "example"]);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        ChildCutTransport {
            root,
            parent,
            child,
            alias: alias.clone(),
            target: target.clone(),
            requests: Arc::clone(&requests),
        },
        config(vec![root]),
    );

    let reply = resolver
        .resolve(Question {
            qname: alias.clone(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();

    assert!(reply.answers.iter().any(|record| {
        record.name.eq_dns(&target) && record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 80))
    }));
    assert!(
        !reply
            .answers
            .iter()
            .any(|record| record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 66)))
    );
    let cached_target = resolver.resolve(Question {
        qname: target.clone(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    });
    assert_eq!(
        cached_target.await.unwrap().answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 80))
    );
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        &[(root, alias.clone()), (parent, alias), (child, target),]
    );
}

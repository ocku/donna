use super::*;

#[tokio::test]
async fn exact_in_bailiwick_glue_is_not_returned_as_a_public_answer() {
    let root = "192.0.2.1:53".parse().unwrap();
    let ipv4_glue = "192.0.2.53:53".parse().unwrap();
    let ipv6_glue = "[2001:db8::53]:53".parse().unwrap();
    let name_server = name(&["ns", "example"]);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        ExactInBailiwickGlueTransport {
            root,
            ipv4_glue,
            ipv6_glue,
            delegated_zone: name(&["example"]),
            name_server: name_server.clone(),
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![root],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let question = Question {
        qname: name_server,
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    let reply = resolver.resolve(question.clone()).await.unwrap();

    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 80))
    );
    assert_ne!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 53))
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_query(&calls[0], root, &question.qname, QueryType::A);
    assert!([ipv4_glue, ipv6_glue].contains(&calls[1].0));
    assert!(calls[1].1.eq_dns(&question.qname));
    assert_eq!(calls[1].2, QueryType::A);
    drop(calls);

    let cached = resolver
        .positive_cache
        .get_question(&question)
        .expect("the authoritative public answer should be cached");
    assert_eq!(
        cached.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 80))
    );
}

#[tokio::test]
async fn unrelated_out_of_bailiwick_additional_is_never_queried() {
    let root = "192.0.2.1:53".parse().unwrap();
    let attacker = "198.51.100.53:53".parse().unwrap();
    let authority = "192.0.2.53:53".parse().unwrap();
    let forged_address = Ipv4Addr::new(203, 0, 113, 66);
    let legitimate_address = Ipv4Addr::new(192, 0, 2, 80);
    let target = name(&["www", "victim", "example"]);
    let name_server = name(&["ns", "provider"]);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        OutOfBailiwickGlueTransport {
            root,
            attacker,
            authority,
            delegated_zone: name(&["victim", "example"]),
            target: target.clone(),
            name_server: name_server.clone(),
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![root],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let question = Question {
        qname: target,
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    let reply = resolver.resolve(question.clone()).await.unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(*calls, [root, root, authority]);
    assert!(!calls.contains(&attacker));
    drop(calls);
    assert!(
        resolver
            .delegation_cache
            .get(&question)
            .unwrap()
            .candidates
            .is_empty()
    );
    assert_eq!(reply.answers[0].rdata, RData::A(legitimate_address));
    assert!(
        reply
            .answers
            .iter()
            .all(|record| record.rdata != RData::A(forged_address))
    );
    let cached = resolver
        .positive_cache
        .get_question(&question)
        .expect("the legitimate authoritative answer should be cached");
    assert_eq!(cached.answers[0].rdata, RData::A(legitimate_address));
    assert!(
        cached
            .answers
            .iter()
            .all(|record| record.rdata != RData::A(forged_address))
    );
    assert!(resolver.negative_cache.get(&question).is_none());

    let name_server_question = Question {
        qname: name_server,
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let cached_name_server = resolver
        .positive_cache
        .get_question(&name_server_question)
        .expect("the independently resolved name-server address should be cached");
    assert_eq!(
        cached_name_server.answers[0].rdata,
        RData::A(match authority.ip() {
            std::net::IpAddr::V4(address) => address,
            std::net::IpAddr::V6(_) => unreachable!(),
        })
    );
}

#[tokio::test]
async fn root_sibling_glue_routes_com_lookup_without_ns_host_lookup_or_caching() {
    let root = "192.0.2.1:53".parse().unwrap();
    let com_server = "192.0.2.53:53".parse().unwrap();
    let first_target = name(&["www", "example", "com"]);
    let second_target = name(&["www", "example-two", "com"]);
    let name_server = name(&["a", "gtld-servers", "net"]);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        RootSiblingGlueTransport {
            root,
            com_server,
            name_server: name_server.clone(),
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![root],
            max_steps: 2,
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let questions = [first_target, second_target].map(|qname| Question {
        qname,
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    });

    for question in &questions {
        let reply = resolver.resolve(question.clone()).await.unwrap();
        assert_eq!(
            reply.answers[0].rdata,
            RData::A(Ipv4Addr::new(192, 0, 2, 80))
        );
        assert!(
            resolver.delegation_cache.get(question).is_none(),
            "a provisional-only referral must be reacquired from its parent"
        );
    }

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_query(&calls[0], root, &questions[0].qname, QueryType::A);
    assert_query(&calls[1], com_server, &questions[0].qname, QueryType::A);
    assert_query(&calls[2], root, &questions[1].qname, QueryType::A);
    assert_query(&calls[3], com_server, &questions[1].qname, QueryType::A);
    assert!(
        calls
            .iter()
            .all(|(_, qname, _)| !qname.eq_dns(&name_server))
    );
    drop(calls);
    for qtype in [QueryType::A, QueryType::AAAA] {
        assert!(
            resolver
                .positive_cache
                .get_question(&Question {
                    qname: name_server.clone(),
                    qtype,
                    qclass: QClassType::Class(ClassType::IN),
                })
                .is_none()
        );
    }
}

#[tokio::test]
async fn follows_a_cname_targets_referral_without_restarting_at_root() {
    let root = "192.0.2.1:53".parse().unwrap();
    let authority = "192.0.2.53:53".parse().unwrap();
    let alias = name(&["alias", "example"]);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        RoutedTransport {
            root,
            authority,
            alias: alias.clone(),
            target: name(&["target", "other"]),
            name_server: name(&["ns", "other"]),
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![root],
            max_steps: 2,
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );

    let reply = resolver
        .resolve(Question {
            qname: alias,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();

    assert_eq!(*calls.lock().unwrap(), [root, authority]);
    assert_eq!(reply.answers.len(), 2);
}

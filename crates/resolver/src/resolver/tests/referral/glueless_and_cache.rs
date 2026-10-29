use super::*;

#[tokio::test]
async fn glueless_referral_tries_second_name_server_after_first_is_unreachable() {
    let root = "192.0.2.1:53".parse().unwrap();
    let dead = "192.0.2.2:53".parse().unwrap();
    let authority = "192.0.2.3:53".parse().unwrap();
    let target = name(&["www", "example"]);
    let delegated_zone = name(&["example"]);
    let ns1 = name(&["ns1", "provider"]);
    let ns2 = name(&["ns2", "provider"]);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        LazyGluelessTransport {
            root,
            dead,
            authority,
            delegated_zone,
            target: target.clone(),
            name_servers: vec![ns1.clone(), ns2.clone()],
            empty_name_server: None,
            dead_name_server: ns1.clone(),
            working_name_server: ns2.clone(),
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![root],
            max_steps: 7,
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );

    let reply = resolver
        .resolve(Question {
            qname: target.clone(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();

    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 80))
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 6);
    assert_query(&calls[0], root, &target, QueryType::A);
    assert_query(&calls[1], root, &ns1, QueryType::A);
    assert_query(&calls[2], dead, &target, QueryType::A);
    assert_query(&calls[3], root, &ns1, QueryType::AAAA);
    assert_query(&calls[4], root, &ns2, QueryType::A);
    assert_query(&calls[5], authority, &target, QueryType::A);
}

#[tokio::test]
async fn glueless_referral_skips_empty_then_tries_later_name_servers_lazily() {
    let root = "192.0.2.1:53".parse().unwrap();
    let dead = "192.0.2.2:53".parse().unwrap();
    let authority = "192.0.2.3:53".parse().unwrap();
    let target = name(&["www", "example"]);
    let delegated_zone = name(&["example"]);
    let ns1 = name(&["ns1", "provider"]);
    let ns2 = name(&["ns2", "provider"]);
    let ns3 = name(&["ns3", "provider"]);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        LazyGluelessTransport {
            root,
            dead,
            authority,
            delegated_zone,
            target: target.clone(),
            name_servers: vec![ns1.clone(), ns2.clone(), ns3.clone()],
            empty_name_server: Some(ns1.clone()),
            dead_name_server: ns2.clone(),
            working_name_server: ns3.clone(),
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![root],
            max_steps: 9,
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );

    let reply = resolver
        .resolve(Question {
            qname: target.clone(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();

    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 80))
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 8);
    assert_query(&calls[0], root, &target, QueryType::A);
    assert_query(&calls[1], root, &ns1, QueryType::A);
    assert_query(&calls[2], root, &ns1, QueryType::AAAA);
    assert_query(&calls[3], root, &ns2, QueryType::A);
    assert_query(&calls[4], dead, &target, QueryType::A);
    assert_query(&calls[5], root, &ns2, QueryType::AAAA);
    assert_query(&calls[6], root, &ns3, QueryType::A);
    assert_query(&calls[7], authority, &target, QueryType::A);
}

#[tokio::test]
async fn exact_in_bailiwick_glue_caches_the_progressing_delegation_but_not_an_answer() {
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

    let resolution = resolver
        .resolve_name_server_addresses(
            std::slice::from_ref(&name_server),
            &[],
            Arc::new(AtomicUsize::new(8)),
            None,
            Arc::new(AlgorithmSignals::default()),
        )
        .await;

    assert_eq!(resolution.addresses, [ipv4_glue]);
    assert_eq!(resolution.pending_name_servers.len(), 1);
    assert!(resolution.pending_name_servers[0].name.eq_dns(&name_server));
    {
        let initial_calls = calls.lock().unwrap();
        assert_eq!(initial_calls.len(), 1);
        assert_query(&initial_calls[0], root, &name_server, QueryType::A);
    }

    for qtype in [QueryType::A, QueryType::AAAA] {
        let question = Question {
            qname: name_server.clone(),
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        };
        assert!(resolver.positive_cache.get_question(&question).is_none());
        assert!(resolver.negative_cache.get(&question).is_none());
    }

    let public_question = Question {
        qname: name_server.clone(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let cached_delegation = resolver
        .delegation_cache
        .get(&public_question)
        .expect("the progressing delegation should be cached");
    assert!(cached_delegation.zone.eq_dns(&name(&["example"])));
    assert!(cached_delegation.candidates.contains(&ipv4_glue));
    assert!(cached_delegation.candidates.contains(&ipv6_glue));

    // Reusing the delegation goes directly to its authoritative server. The
    // root discovery query is not repeated, and glue still is not surfaced as
    // a public answer.
    let reply = resolver.resolve(public_question).await.unwrap();
    assert_eq!(
        reply.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 80))
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_query(&calls[0], root, &name_server, QueryType::A);
    assert!([ipv4_glue, ipv6_glue].contains(&calls[1].0));
    assert!(calls[1].1.eq_dns(&name_server));
    assert_eq!(calls[1].2, QueryType::A);
}

#[tokio::test]
async fn exact_glue_from_a_non_progressing_referral_is_not_cached() {
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
            delegated_zone: DomainName::root(),
            name_server: name_server.clone(),
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![root],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );

    let resolution = resolver
        .resolve_name_server_addresses(
            std::slice::from_ref(&name_server),
            &[],
            Arc::new(AtomicUsize::new(8)),
            None,
            Arc::new(AlgorithmSignals::default()),
        )
        .await;

    assert_eq!(resolution.addresses, [ipv4_glue]);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert!(
        resolver
            .delegation_cache
            .get(&Question {
                qname: name_server,
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            })
            .is_none()
    );
}

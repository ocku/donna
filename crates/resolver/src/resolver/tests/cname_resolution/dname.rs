use super::*;

#[tokio::test]
async fn forged_dname_redirection_is_not_treated_as_an_independent_cname() {
    let q = question(&["www", "old", "example"]);
    let mut misleading = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![
            ResourceRecord {
                name: name(&["old", "example"]),
                rtype: RecordType::DNAME,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::DNAME(name(&["new", "example"])),
            },
            ResourceRecord {
                name: q.qname.clone(),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::CNAME(name(&["wrong", "example"])),
            },
        ],
    );
    misleading.questions = vec![q.clone()];
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![misleading])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));
    assert!(matches!(
        resolver.resolve(q).await,
        Err(ResolveError::NoReachableServer)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn follows_dname_with_or_without_the_server_synthesized_cname() {
    for synthesize in [false, true] {
        let q = question(&["www", "old", "example"]);
        let target = name(&["www", "new", "other"]);
        let dname = ResourceRecord {
            name: name(&["old", "example"]),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::DNAME(name(&["new", "other"])),
        };
        let mut answers = vec![dname];
        if synthesize {
            answers.push(ResourceRecord {
                name: q.qname.clone(),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 120,
                rdata: RData::CNAME(target.clone()),
            });
        }
        let redirect = response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            answers,
        );
        let terminal = response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(target.clone(), 60)],
        );
        let transport = MockTransport {
            replies: Arc::new(Mutex::new(vec![redirect, terminal])),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let requests = Arc::clone(&transport.requests);
        let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));
        let reply = resolver.resolve(q.clone()).await.unwrap();
        assert_eq!(
            reply.answers.iter().map(|rr| rr.rtype).collect::<Vec<_>>(),
            vec![RecordType::DNAME, RecordType::CNAME, RecordType::A]
        );
        assert!(matches!(&reply.answers[1].rdata, RData::CNAME(name) if name.eq_dns(&target)));
        assert!(reply.answers[1].ttl <= reply.answers[0].ttl);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].questions[0].qname.eq_dns(&target));
    }
}

#[tokio::test]
async fn dname_cname_question_returns_synthesized_alias_and_dname() {
    let mut q = question(&["www", "old", "example"]);
    q.qtype = QueryType::CNAME;
    let redirect = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![ResourceRecord {
            name: name(&["old", "example"]),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::DNAME(name(&["new", "other"])),
        }],
    );
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![redirect])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));
    let reply = resolver.resolve(q).await.unwrap();
    assert_eq!(
        reply.answers.iter().map(|rr| rr.rtype).collect::<Vec<_>>(),
        vec![RecordType::DNAME, RecordType::CNAME]
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn dname_overflow_returns_yxdomain_with_the_proof() {
    let q = question(&["www", "old", "example"]);
    let target = DomainName::from_labels(vec![
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 60],
    ])
    .unwrap();
    let redirect = response(
        Headers {
            qr: true,
            aa: true,
            rcode: RCode::YXDomain,
            ..Headers::default()
        },
        vec![ResourceRecord {
            name: name(&["old", "example"]),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::DNAME(target),
        }],
    );
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![redirect])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));
    let reply = resolver.resolve(q).await.unwrap();
    assert_eq!(reply.headers.rcode, RCode::YXDomain);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].rtype, RecordType::DNAME);
}

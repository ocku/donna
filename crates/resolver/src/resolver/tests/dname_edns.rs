use super::*;

fn overflow_response(extended_rcode: u8) -> Message {
    let target = DomainName::from_labels(vec![
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 60],
    ])
    .unwrap();
    let mut reply = response(
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
    reply.additionals.push(
        dns::Edns {
            extended_rcode,
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );
    reply
}

#[tokio::test]
async fn dname_overflow_consumes_upstream_opt() {
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![overflow_response(0)])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));
    let reply = resolver
        .resolve(question(&["www", "old", "example"]))
        .await
        .unwrap();

    assert_eq!(reply.headers.rcode, RCode::YXDomain);
    assert_eq!(reply.answers.len(), 1);
    assert!(reply.edns().unwrap().is_none());
}

#[tokio::test]
async fn extended_error_with_yxdomain_header_is_not_a_dname_overflow() {
    for high_bits in [1, 16, 255] {
        let query = question(&["www", "old", "example"]);
        let answer = response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 1)],
        );
        let transport = MockTransport {
            replies: Arc::new(Mutex::new(vec![overflow_response(high_bits), answer])),
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

        assert_eq!(reply.headers.rcode, RCode::Ok, "extended RCODE {high_bits}");
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].rtype, RecordType::A);
        assert!(reply.edns().unwrap().is_none());
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn malformed_or_unsupported_edns_on_overflow_is_not_accepted() {
    for bad_edns in ["duplicate", "misplaced", "unsupported"] {
        let query = question(&["www", "old", "example"]);
        let mut invalid = overflow_response(0);
        match bad_edns {
            "duplicate" => invalid.additionals.push(dns::Edns::new(1232).into_record()),
            "misplaced" => invalid.answers.push(invalid.additionals.pop().unwrap()),
            "unsupported" => {
                invalid.additionals = vec![
                    dns::Edns {
                        version: 1,
                        ..dns::Edns::new(1232)
                    }
                    .into_record(),
                ];
            }
            _ => unreachable!(),
        }
        let answer = response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 1)],
        );
        let transport = MockTransport {
            replies: Arc::new(Mutex::new(vec![invalid, answer])),
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
        assert_eq!(reply.headers.rcode, RCode::Ok, "{bad_edns}");
        assert_eq!(reply.answers[0].rtype, RecordType::A, "{bad_edns}");
        assert_eq!(requests.lock().unwrap().len(), 2, "{bad_edns}");
    }
}

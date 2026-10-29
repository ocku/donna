use super::*;

#[test]
fn transactional_retention_preserves_popularity_and_rejects_stale_or_expired_identity() {
    let cache = PositiveCache::new(2);
    let a = question(1);
    let mut b = question(2);
    b.questions[0].qname = DomainName::from_dotted("other.example.").unwrap();
    let mut c = question(3);
    c.questions[0].qname = DomainName::from_dotted("third.example.").unwrap();
    for request in [&a, &b] {
        assert!(cache.insert(
            request,
            &answer(request, ClassType::IN, true),
            Duration::from_secs(60)
        ));
    }
    let selected = cache.select_question(&a.questions[0]).unwrap();
    let identity = selected.identity();
    for _ in 0..2 {
        assert!(cache.select_question(&b.questions[0]).is_some());
    }
    for _ in 0..100 {
        assert!(cache.retain_question(&a.questions[0], &identity).is_some());
    }
    {
        let entries = cache.entries.lock().unwrap();
        let index = cache.find_question(&entries, &a.questions[0]).unwrap();
        assert_eq!(
            entries.values[index].hits, 1,
            "provenance rechecks are not client uses"
        );
    }
    assert!(cache.insert(
        &c,
        &answer(&c, ClassType::IN, true),
        Duration::from_secs(60)
    ));
    assert!(
        cache.retain_question(&a.questions[0], &identity).is_none(),
        "least-used A must still be eviction victim"
    );
    assert!(cache.get(&b).is_some());

    let cache = PositiveCache::new(1);
    assert!(cache.insert(
        &a,
        &answer(&a, ClassType::IN, true),
        Duration::from_secs(60)
    ));
    let old = cache.select_question(&a.questions[0]).unwrap();
    let mut replacement = answer(&a, ClassType::IN, true);
    replacement.answers[0].rdata = RData::A(Ipv4Addr::new(192, 0, 2, 2));
    assert!(cache.insert(&a, &replacement, Duration::from_secs(60)));
    assert!(
        cache
            .retain_question(&a.questions[0], &old.identity())
            .is_none()
    );
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 0);
    let current = cache.select_question(&a.questions[0]).unwrap();
    assert!(
        cache
            .retain_question(&a.questions[0], &current.identity())
            .is_some()
    );
    let expired = {
        let mut entries = cache.entries.lock().unwrap();
        assert_eq!(entries.values[0].hits, 1);
        entries.modify(0, |entry| {
            entry.expires_at = Instant::now() - Duration::from_secs(1)
        });
        // This identity matches the expired object exactly, so rejection must
        // check liveness rather than merely fail an identity comparison.
        super::super::SelectedPositive::new(&entries.values[0], Instant::now())
    };
    assert!(
        cache
            .retain_question(&a.questions[0], &expired.identity())
            .is_none()
    );
    let entries = cache.entries.lock().unwrap();
    assert_eq!(
        entries.values.len(),
        1,
        "read-only retention does not remove expired entries"
    );
    assert_eq!(entries.values[0].hits, 1);
}

fn answer(request: &Message, class: ClassType, authoritative: bool) -> Message {
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.headers.aa = authoritative;
    reply.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: if matches!(request.questions[0].qtype, QueryType::TXT | QueryType::ANY) {
            RecordType::TXT
        } else {
            RecordType::A
        },
        class,
        ttl: 60,
        rdata: if matches!(request.questions[0].qtype, QueryType::TXT | QueryType::ANY) {
            RData::TXT(vec![b"class test".to_vec()])
        } else {
            RData::A(Ipv4Addr::new(192, 0, 2, 1))
        },
    });
    reply
}

#[test]
fn aggregate_trust_checks_and_distinct_classes_share_the_owner_index_safely() {
    let cache = PositiveCache::new(10);
    let mut concrete = question(1);
    concrete.questions[0].qtype = QueryType::TXT;
    let mut any = concrete.clone();
    any.questions[0].qtype = QueryType::ANY;
    assert!(cache.insert(
        &any,
        &answer(&any, ClassType::IN, true),
        Duration::from_secs(60)
    ));
    assert!(!cache.insert(
        &concrete,
        &answer(&concrete, ClassType::IN, false),
        Duration::from_secs(60)
    ));
    let mut chaos = concrete.clone();
    chaos.questions[0].qclass = QClassType::Class(ClassType::CH);
    assert!(cache.insert(
        &chaos,
        &answer(&chaos, ClassType::CH, false),
        Duration::from_secs(60)
    ));
    assert!(cache.get(&any).is_some());
    assert!(cache.get(&chaos).is_some());
    assert!(cache.get(&concrete).is_none());
}

#[test]
fn expired_exact_key_replacement_survives_a_large_expiry_backlog() {
    let cache = PositiveCache::new(128);
    let mut requests = Vec::new();
    for index in 0..100 {
        let mut request = question(1);
        request.questions[0].qname =
            DomainName::from_dotted(&format!("host-{index}.example.")).unwrap();
        assert!(cache.insert(
            &request,
            &answer(&request, ClassType::IN, true),
            Duration::from_secs(60)
        ));
        requests.push(request);
    }
    {
        let mut entries = cache.entries.lock().unwrap();
        let now = Instant::now();
        for index in 0..100 {
            entries.modify(index, |entry| {
                entry.expires_at = now - Duration::from_secs(if index == 99 { 1 } else { 10 })
            });
        }
    }
    let request = &requests[99];
    assert!(cache.insert(
        request,
        &answer(request, ClassType::IN, true),
        Duration::from_secs(60)
    ));
    assert!(
        cache.get(request).is_some(),
        "an expired duplicate must not mask its replacement"
    );
    let entries = cache.entries.lock().unwrap();
    assert_eq!(
        entries
            .values
            .iter()
            .filter(|entry| entry.key == CacheKey::new(&request.questions[0]))
            .count(),
        1
    );
}

#[test]
fn bounded_owner_reads_match_original_hash_lookup_across_types_classes_and_names() {
    for qname in [
        DomainName::root(),
        DomainName::from_dotted("WWW.Example.").unwrap(),
        DomainName::from_labels(vec![vec![0, b'A', 255], vec![b'.', b'Z']]).unwrap(),
        DomainName::from_labels(vec![vec![b'A']; 127]).unwrap(),
    ] {
        for count in [0, 1, 3, 4, 5, 7, 8, 9, 16] {
            let cache = PositiveCache::new(64);
            for n in 0..count {
                for class in [ClassType::IN, ClassType::CH] {
                    let mut request = question(1);
                    request.questions[0] = Question {
                        qname: qname.clone(),
                        qtype: QueryType::Unknown(65000 + n),
                        qclass: QClassType::Class(class),
                    };
                    let mut reply = request.clone();
                    reply.headers.qr = true;
                    reply.headers.aa = true;
                    reply.answers.push(ResourceRecord {
                        name: qname.clone(),
                        rtype: RecordType::Unknown(65000 + n),
                        class,
                        ttl: 60,
                        rdata: RData::Unknown(vec![n as u8]),
                    });
                    assert!(cache.insert(&request, &reply, Duration::from_secs(60)));
                }
            }
            let entries = cache.entries.lock().unwrap();
            for n in 0..=count {
                for qclass in [
                    QClassType::Class(ClassType::IN),
                    QClassType::Class(ClassType::CH),
                    QClassType::Class(ClassType::Unknown(1)),
                    QClassType::ANY,
                    QClassType::Unknown(65000),
                ] {
                    let query = Question {
                        qname: qname.clone(),
                        qtype: QueryType::Unknown(65000 + n),
                        qclass,
                    };
                    for spelling in [
                        query.qname.clone(),
                        DomainName::from_labels(
                            query
                                .qname
                                .as_ref()
                                .iter()
                                .map(|label| label.to_ascii_lowercase())
                                .collect(),
                        )
                        .unwrap(),
                    ] {
                        let query = Question {
                            qname: spelling,
                            ..query.clone()
                        };
                        assert_eq!(
                            cache.find_question(&entries, &query),
                            entries.find_question(cache.hash_question(&query), &query)
                        );
                    }
                }
            }
        }
    }
}

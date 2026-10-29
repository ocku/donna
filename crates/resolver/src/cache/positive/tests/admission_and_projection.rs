use super::*;

#[test]
fn does_not_cache_non_standard_queries() {
    let cache = PositiveCache::new(1);
    let mut request = question(1);
    request.headers.opcode = OpCode::IQuery;
    let mut reply = request.clone();
    reply.headers.qr = true;
    cache.insert(&request, &reply, Duration::from_secs(60));

    assert!(cache.get(&request).is_none());
}

#[test]
fn stores_records_and_rebuilds_client_fields() {
    let cache = PositiveCache::new(1);
    let request = question(1);
    let mut reply = request.clone();
    reply.headers = Headers {
        id: request.headers.id,
        qr: true,
        rd: true,
        aa: true,
        ra: true,
        ..Headers::default()
    };
    reply.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    });
    cache.insert(&request, &reply, Duration::from_secs(60));

    let mut another_client = question(2);
    another_client.questions[0].qname =
        DomainName::from_labels(vec![b"www".to_vec(), b"example".to_vec()]).unwrap();
    let hit = cache.get(&another_client).expect("cached response");
    assert_eq!(hit.headers.id, 2);
    assert!(hit.headers.rd);
    assert!(!hit.headers.aa);
    assert!(!hit.headers.ra);
    assert_eq!(hit.answers.len(), 1);
    assert!(hit.answers[0].ttl <= 60);
}

#[test]
fn aggregate_queries_require_an_authoritative_source() {
    let target = DomainName::from_labels(vec![b"mail".to_vec(), b"example".to_vec()]).unwrap();
    for (qtype, rtype, rdata) in [
        (
            QueryType::ANY,
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ),
        (QueryType::MAILA, RecordType::MD, RData::MD(target.clone())),
        (QueryType::MAILB, RecordType::MB, RData::MB(target.clone())),
    ] {
        let cache = PositiveCache::new(1);
        let mut request = question(1);
        request.questions[0].qtype = qtype;
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.answers.push(ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype,
            class: ClassType::IN,
            ttl: 60,
            rdata,
        });

        assert!(!cache.insert(&request, &reply, Duration::from_secs(60)));
        assert!(cache.get(&request).is_none());
    }

    let cache = PositiveCache::new(1);
    let mut request = question(1);
    request.questions[0].qclass = QClassType::ANY;
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    });

    assert!(!cache.insert(&request, &reply, Duration::from_secs(60)));
}

#[test]
fn meta_types_are_never_cached_or_used_as_ttls() {
    for code in [41, 249, 250] {
        for meta_ttl in [0, 1 << 15] {
            let rtype = match code {
                41 => RecordType::OPT,
                250 => RecordType::TSIG,
                code => RecordType::Unknown(code),
            };
            let cache = PositiveCache::new(1);
            let mut request = question(1);
            request.questions[0].qtype = QueryType::ANY;
            let mut reply = request.clone();
            reply.headers.qr = true;
            reply.headers.aa = true;
            reply.answers.push(ResourceRecord {
                name: request.questions[0].qname.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 60_000,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            });
            reply.answers.push(ResourceRecord {
                name: request.questions[0].qname.clone(),
                rtype,
                class: ClassType::IN,
                ttl: meta_ttl,
                rdata: RData::Unknown(Vec::new()),
            });

            cache.insert(&request, &reply, Duration::from_secs(60_000));

            let hit = cache.get(&request).expect("cached response");
            assert!(
                hit.answers
                    .iter()
                    .all(|record| !record.rtype.is_meta_type())
            );
            assert!(hit.authorities.is_empty());
            assert!(hit.additionals.is_empty());
            let entries = cache
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            assert!(
                entries.values[0]
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    > Duration::from_secs(50_000)
            );
            assert!(
                entries.values[0]
                    .response
                    .answers
                    .iter()
                    .all(|record| !record.rtype.is_meta_type())
            );
        }
    }
}

#[test]
fn rejects_cname_coexistence_before_projecting_requested_records() {
    let request = question(1);
    let qname = request.questions[0].qname.clone();
    let alias = DomainName::from_labels(vec![b"alias".to_vec(), b"example".to_vec()]).unwrap();
    let other = DomainName::from_labels(vec![b"other".to_vec(), b"example".to_vec()]).unwrap();
    let cname = |name: &DomainName, target: &DomainName| ResourceRecord {
        name: name.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target.clone()),
    };
    let address = |name: &DomainName| ResourceRecord {
        name: name.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };

    for answers in [
        vec![cname(&qname, &alias), address(&qname)],
        vec![cname(&qname, &alias), cname(&qname, &other)],
        vec![
            cname(&qname, &alias),
            cname(&alias, &other),
            address(&alias),
        ],
    ] {
        let cache = PositiveCache::new(1);
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.answers = answers;
        cache.insert(&request, &reply, Duration::from_secs(60));
        assert!(cache.get(&request).is_none());
    }

    for qtype in [QueryType::CNAME, QueryType::ANY] {
        let cache = PositiveCache::new(1);
        let mut request = request.clone();
        request.questions[0].qtype = qtype;
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.headers.aa = true;
        reply.answers = vec![cname(&qname, &alias), address(&alias)];
        cache.insert(&request, &reply, Duration::from_secs(60));
        let hit = cache.get(&request).expect("direct CNAME answer");
        assert_eq!(hit.answers.len(), 1);
        assert_eq!(hit.answers[0].rtype, RecordType::CNAME);
    }
}

#[test]
fn cname_composites_are_not_stored_as_single_ranked_entries() {
    let request = question(1);
    let alias = DomainName::from_labels(vec![b"alias".to_vec(), b"example".to_vec()]).unwrap();
    let direct = |last_octet| {
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.headers.aa = true;
        reply.answers.push(ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
        });
        reply
    };
    let mut composite = request.clone();
    composite.headers.qr = true;
    composite.headers.aa = true;
    composite.answers.extend([
        ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CNAME(alias.clone()),
        },
        ResourceRecord {
            name: alias,
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        },
    ]);

    let cache = PositiveCache::new(1);
    cache.insert(&request, &direct(1), Duration::from_secs(60));
    cache.insert(&request, &composite, Duration::from_secs(60));
    assert_eq!(
        cache.get(&request).unwrap().answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );

    let cache = PositiveCache::new(1);
    assert!(!cache.insert(&request, &composite, Duration::from_secs(60)));
    assert!(cache.get(&request).is_none());
}

#[test]
fn authoritative_rrset_ttls_are_normalized_but_non_authoritative_ones_are_rejected() {
    let request = question(1);
    let malformed = |authoritative| {
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.headers.aa = authoritative;
        for (ttl, last_octet) in [(60, 1), (30, 2)] {
            reply.answers.push(ResourceRecord {
                name: request.questions[0].qname.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
            });
        }
        reply
    };

    let cache = PositiveCache::new(1);
    cache.insert(&request, &malformed(true), Duration::from_secs(60));
    let hit = cache
        .get(&request)
        .expect("normalized authoritative response");
    assert_eq!(hit.answers.len(), 2);
    assert!(hit.answers.iter().all(|record| record.ttl <= 30));
    assert_eq!(hit.answers[0].ttl, hit.answers[1].ttl);

    let cache = PositiveCache::new(1);
    cache.insert(&request, &malformed(false), Duration::from_secs(60));
    assert!(cache.get(&request).is_none());

    let alias = DomainName::from_labels(vec![b"alias".to_vec(), b"example".to_vec()]).unwrap();
    let mut composite = request.clone();
    composite.headers.qr = true;
    composite.headers.aa = true;
    composite.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(alias.clone()),
    });
    for (ttl, last_octet) in [(60, 1), (30, 2)] {
        composite.answers.push(ResourceRecord {
            name: alias.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
        });
    }
    let cache = PositiveCache::new(1);
    cache.insert(&request, &composite, Duration::from_secs(60));
    assert!(cache.get(&request).is_none());
}

#[test]
fn ttl_normalization_groups_names_case_insensitively_and_skips_rrsigs() {
    let upper = ResourceRecord {
        name: DomainName::from_labels(vec![b"EXAMPLE".to_vec()]).unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let lower = ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        ttl: 30,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        ..upper.clone()
    };
    let signature = ResourceRecord {
        name: lower.name.clone(),
        rtype: RecordType::RRSIG,
        ttl: 90,
        rdata: RData::RRSIG(dns::Rrsig {
            type_covered: u16::from(RecordType::A),
            algorithm: 15,
            labels: 1,
            original_ttl: 90,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: DomainName::root(),
            signature: vec![1],
        }),
        ..lower.clone()
    };
    let mut records = vec![upper, lower, signature];

    normalize_rrset_ttls(&mut records);

    assert_eq!(records[0].ttl, 30);
    assert_eq!(records[1].ttl, 30);
    assert_eq!(records[2].ttl, 90);
}

#[test]
fn authoritative_any_caches_answer_and_covering_signature_once() {
    let cache = PositiveCache::new(1);
    let mut request = question(1);
    request.questions[0].qtype = QueryType::ANY;
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.headers.aa = true;
    reply.answers = vec![
        ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        },
        ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype: RecordType::RRSIG,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::RRSIG(dns::Rrsig {
                type_covered: u16::from(RecordType::A),
                algorithm: 15,
                labels: 2,
                original_ttl: 60,
                signature_expiration: 2,
                signature_inception: 1,
                key_tag: 1,
                signer_name: DomainName::root(),
                signature: vec![1],
            }),
        },
    ];
    assert!(cache.insert(&request, &reply, Duration::from_secs(60)));
    let hit = cache.get(&request).expect("authoritative ANY cached");
    assert_eq!(hit.answers.len(), 2);
    for (actual, expected) in hit.answers.iter().zip(&reply.answers) {
        assert_eq!(actual.rtype, expected.rtype);
        assert_eq!(actual.rdata, expected.rdata);
    }
}

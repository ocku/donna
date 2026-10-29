use super::*;

#[test]
fn rejects_literal_wildcard_questions_and_zero_effective_ttl() {
    let mut request = question(1);
    request.questions[0].qname =
        DomainName::from_labels(vec![b"*".to_vec(), b"example".to_vec()]).unwrap();
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    });
    let cache = PositiveCache::new(1);
    cache.insert(&request, &reply, Duration::from_secs(60));
    assert!(cache.get(&request).is_none());

    let request = question(2);
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
    });
    cache.insert(&request, &reply, Duration::ZERO);
    assert!(cache.get(&request).is_none());
    assert!(
        cache
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values
            .is_empty()
    );
}

#[test]
fn rrset_replacement_is_coherent_across_query_type_keys() {
    let cache = PositiveCache::new(4);
    let mut any_request = question(1);
    any_request.questions[0].qtype = QueryType::ANY;
    let mut any_reply = any_request.clone();
    any_reply.headers.qr = true;
    any_reply.headers.aa = true;
    any_reply.answers.extend([
        ResourceRecord {
            name: any_request.questions[0].qname.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        },
        ResourceRecord {
            name: any_request.questions[0].qname.clone(),
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::TXT(vec![b"old aggregate".to_vec()]),
        },
    ]);
    assert!(cache.insert(&any_request, &any_reply, Duration::from_secs(60)));

    let request = question(1);
    let replacement = |authoritative| {
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.headers.aa = authoritative;
        reply.answers.push(ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        });
        reply
    };

    assert!(!cache.insert(&request, &replacement(false), Duration::from_secs(60)));
    assert!(cache.get(&any_request).is_some());
    assert!(cache.get(&request).is_none());

    assert!(cache.insert(&request, &replacement(true), Duration::from_secs(60)));
    assert!(cache.get(&any_request).is_none());
    assert_eq!(
        cache.get(&request).unwrap().answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 2))
    );
}

#[test]
fn cache_replacement_preserves_authoritative_trust_rank() {
    let request = question(1);
    let reply = |authoritative, last_octet| {
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.headers.aa = authoritative;
        reply.answers.push(ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
        });
        reply
    };
    let answer = |message: Message| message.answers[0].rdata.clone();

    let cache = PositiveCache::new(1);
    cache.insert(&request, &reply(true, 1), Duration::from_secs(60));
    cache.insert(&request, &reply(false, 2), Duration::from_secs(60));
    assert_eq!(
        answer(cache.get(&request).expect("authoritative cached response")),
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );

    cache.insert(&request, &reply(true, 3), Duration::from_secs(60));
    assert_eq!(
        answer(cache.get(&request).expect("equal-rank cached response")),
        RData::A(Ipv4Addr::new(192, 0, 2, 3))
    );

    let cache = PositiveCache::new(1);
    cache.insert(&request, &reply(false, 4), Duration::from_secs(60));
    cache.insert(&request, &reply(true, 5), Duration::from_secs(60));
    assert_eq!(
        answer(cache.get(&request).expect("higher-rank cached response")),
        RData::A(Ipv4Addr::new(192, 0, 2, 5))
    );
}

#[test]
fn does_not_cache_responses_that_do_not_match_the_request() {
    for reply_headers in [
        Headers {
            id: 2,
            qr: true,
            rd: true,
            ..Headers::default()
        },
        Headers {
            id: 1,
            qr: true,
            rd: false,
            ..Headers::default()
        },
    ] {
        let cache = PositiveCache::new(1);
        let request = question(1);
        let mut reply = request.clone();
        reply.headers = reply_headers;
        reply.answers.push(ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        });
        cache.insert(&request, &reply, Duration::from_secs(60));
        assert!(cache.get(&request).is_none());
    }
}

#[test]
fn does_not_cache_negative_error_or_referral_responses() {
    let cache = PositiveCache::new(1);
    let request = question(1);
    let authority = ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(DomainName::root()),
    };

    for rcode in [RCode::NameError, RCode::ServerFailure] {
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.headers.rcode = rcode;
        reply.authorities.push(authority.clone());
        cache.insert(&request, &reply, Duration::from_secs(60));
        assert!(cache.get(&request).is_none());
    }

    let mut referral = request.clone();
    referral.headers.qr = true;
    referral.authorities.push(authority);
    cache.insert(&request, &referral, Duration::from_secs(60));
    assert!(cache.get(&request).is_none());
}

#[test]
fn does_not_cache_truncated_responses() {
    let cache = PositiveCache::new(1);
    let request = question(1);
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.headers.tc = true;
    reply.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    });
    cache.insert(&request, &reply, Duration::from_secs(60));
    assert!(cache.get(&request).is_none());
}

#[test]
fn does_not_cache_zero_or_invalid_high_bit_ttl_responses() {
    let cache = PositiveCache::new(1);
    let request = question(1);
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    });
    cache.insert(&request, &reply, Duration::from_secs(60));
    assert!(cache.get(&request).is_none());

    reply.answers[0].ttl = i32::MAX as u32 + 1;
    cache.insert(&request, &reply, Duration::from_secs(60));
    assert!(cache.get(&request).is_none());
}

#[test]
fn legacy_aggregate_query_type_overlap_is_explicit_and_symmetric() {
    for (aggregate, members) in [
        (
            QueryType::ANY,
            &[QueryType::A, QueryType::TXT, QueryType::CAA][..],
        ),
        (QueryType::MAILA, &[QueryType::MD, QueryType::MF][..]),
        (
            QueryType::MAILB,
            &[QueryType::MB, QueryType::MG, QueryType::MR][..],
        ),
    ] {
        for member in members {
            assert!(query_types_overlap(aggregate.into(), (*member).into()));
            assert!(query_types_overlap((*member).into(), aggregate.into()));
        }
    }

    for excluded in [
        QueryType::IXFR,
        QueryType::AXFR,
        QueryType::MAILB,
        QueryType::MAILA,
        QueryType::Unknown(41),
    ] {
        assert!(!query_types_overlap(QueryType::ANY.into(), excluded.into()));
    }
}

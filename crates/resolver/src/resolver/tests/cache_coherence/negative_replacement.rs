use super::*;

#[test]
fn nxdomain_replaces_owner_positives_and_nodata() {
    let resolver = new_resolver();
    let a = question(QueryType::A);
    let txt = question(QueryType::TXT);
    resolver.cache_positive_entries(1, &address(&a, false), &a);
    resolver.cache_positive_entries(1, &text(&txt, false), &txt);

    let nx = negative(&a, RCode::NameError, true);
    resolver.cache_response_entries(1, &nx, &a, &a, true);

    assert!(positive_hit(&resolver, &a).is_none());
    assert!(positive_hit(&resolver, &txt).is_none());
    assert_eq!(
        resolver.negative_cache.get(&txt).unwrap().headers.rcode,
        RCode::NameError
    );

    let nodata = negative(&a, RCode::Ok, true);
    resolver.cache_response_entries(1, &nodata, &a, &a, true);
    assert_eq!(
        resolver.negative_cache.get(&a).unwrap().headers.rcode,
        RCode::Ok
    );
    assert!(resolver.negative_cache.get(&txt).is_none());

    resolver.cache_response_entries(1, &nx, &a, &a, true);
    assert_eq!(
        resolver.negative_cache.get(&a).unwrap().headers.rcode,
        RCode::NameError
    );
}

#[test]
fn nodata_removes_only_the_exact_ordinary_positive_type() {
    let resolver = new_resolver();
    let a = question(QueryType::A);
    let txt = question(QueryType::TXT);
    resolver.cache_positive_entries(1, &address(&a, false), &a);
    resolver.cache_positive_entries(1, &text(&txt, false), &txt);

    let nodata = negative(&a, RCode::Ok, true);
    resolver.cache_response_entries(1, &nodata, &a, &a, true);

    assert!(positive_hit(&resolver, &a).is_none());
    assert!(positive_hit(&resolver, &txt).is_some());
    assert_eq!(
        resolver.negative_cache.get(&a).unwrap().headers.rcode,
        RCode::Ok
    );
    assert!(resolver.negative_cache.get(&txt).is_none());
}

#[test]
fn effective_negative_ttl_never_exceeds_the_positive_cache_limit() {
    let resolver = resolver_with_ttl_limits(Duration::from_secs(2), Duration::from_secs(30));
    let query = question(QueryType::A);
    let negative = negative(&query, RCode::NameError, true);

    resolver.cache_response_entries(1, &negative, &query, &query, true);
    let cached = resolver.negative_cache.get(&query).unwrap();

    assert_eq!(cached.authorities.len(), 1);
    assert!(cached.authorities[0].ttl <= 2);
}

#[test]
fn replacing_a_concrete_rrset_invalidates_stale_aggregate_keys() {
    let resolver = new_resolver();
    let any = question(QueryType::ANY);
    let a = question(QueryType::A);
    let txt = question(QueryType::TXT);
    let mut aggregate = positive(
        &any,
        RecordType::A,
        RData::A("192.0.2.1".parse().unwrap()),
        true,
    );
    aggregate.answers.push(ResourceRecord {
        name: any.qname.clone(),
        rtype: RecordType::TXT,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::TXT(vec![b"still current".to_vec()]),
    });

    resolver.cache_positive_entries(1, &aggregate, &any);
    assert!(positive_hit(&resolver, &any).is_some());
    assert!(positive_hit(&resolver, &a).is_some());
    assert!(positive_hit(&resolver, &txt).is_some());

    let replacement = positive(
        &a,
        RecordType::A,
        RData::A("192.0.2.2".parse().unwrap()),
        true,
    );
    resolver.cache_positive_entries(1, &replacement, &a);

    assert!(positive_hit(&resolver, &any).is_none());
    assert_eq!(
        positive_hit(&resolver, &a).unwrap().answers[0].rdata,
        RData::A("192.0.2.2".parse().unwrap())
    );
    assert!(positive_hit(&resolver, &txt).is_some());
}

#[test]
fn concrete_nodata_removes_only_matching_positive_aggregate_data() {
    for (aggregate_type, members) in aggregate_families() {
        for &denied_type in members {
            let resolver = new_resolver();
            let aggregate_question = question(aggregate_type);
            resolver.cache_positive_entries(
                1,
                &aggregate_positive(aggregate_type, members),
                &aggregate_question,
            );

            let denied_question = question(query_type_for_record(denied_type));
            let nodata = negative(&denied_question, RCode::Ok, true);
            resolver.cache_response_entries(1, &nodata, &denied_question, &denied_question, true);

            assert!(positive_hit(&resolver, &aggregate_question).is_none());
            assert!(positive_hit(&resolver, &denied_question).is_none());
            assert!(resolver.negative_cache.get(&denied_question).is_some());
            for &preserved_type in members {
                if preserved_type != denied_type {
                    assert!(
                        positive_hit(&resolver, &question(query_type_for_record(preserved_type)),)
                            .is_some()
                    );
                }
            }
        }
    }
}

#[test]
fn aggregate_nodata_is_removed_by_matching_concrete_positive_data() {
    for (aggregate_type, members) in aggregate_families() {
        for &rtype in members {
            let resolver = new_resolver();
            let aggregate_question = question(aggregate_type);
            let nodata = negative(&aggregate_question, RCode::Ok, true);
            resolver.cache_response_entries(
                1,
                &nodata,
                &aggregate_question,
                &aggregate_question,
                true,
            );

            let concrete_question = question(query_type_for_record(rtype));
            let reply = positive(&concrete_question, rtype, aggregate_rdata(rtype), true);
            resolver.cache_positive_entries(1, &reply, &concrete_question);

            assert!(positive_hit(&resolver, &concrete_question).is_some());
            assert!(resolver.negative_cache.get(&aggregate_question).is_none());
        }
    }
}

#[test]
fn dname_target_nxdomain_does_not_create_a_negative_for_the_alias() {
    let resolver = new_resolver();
    let query = question(QueryType::A);
    let mut reply = negative(&query, RCode::NameError, true);
    reply.answers = vec![
        ResourceRecord {
            name: name(&["example"]),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::DNAME(name(&["target", "example"])),
        },
        ResourceRecord {
            name: query.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::CNAME(name(&["owner", "target", "example"])),
        },
    ];
    resolver.cache_response_entries(1, &reply, &query, &query, true);
    assert!(resolver.negative_cache.get(&query).is_none());
    assert!(positive_hit(&resolver, &query).is_none());
    resolver.cache_validated_response(&reply, &query);
    assert!(resolver.negative_cache.get(&query).is_none());
}

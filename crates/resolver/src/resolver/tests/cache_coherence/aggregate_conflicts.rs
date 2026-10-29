use super::*;

#[test]
fn concrete_nodata_keeps_partial_any_without_the_denied_type() {
    let resolver = new_resolver();
    let any = question(QueryType::ANY);
    let a = question(QueryType::A);
    let txt = question(QueryType::TXT);
    resolver.cache_positive_entries(
        1,
        &aggregate_positive(QueryType::ANY, &[RecordType::TXT]),
        &any,
    );

    let nodata = negative(&a, RCode::Ok, true);
    resolver.cache_response_entries(1, &nodata, &a, &a, true);

    assert!(positive_hit(&resolver, &any).is_some());
    assert!(positive_hit(&resolver, &txt).is_some());
    assert!(resolver.negative_cache.get(&a).is_some());
}

#[test]
fn partial_positive_aggregate_keeps_unrepresented_aggregate_nodata() {
    let resolver = new_resolver();
    let maila = question(QueryType::MAILA);
    let maila_nodata = negative(&maila, RCode::Ok, true);
    resolver.cache_response_entries(1, &maila_nodata, &maila, &maila, true);

    let any = question(QueryType::ANY);
    resolver.cache_positive_entries(
        1,
        &aggregate_positive(QueryType::ANY, &[RecordType::A]),
        &any,
    );

    assert!(positive_hit(&resolver, &any).is_some());
    assert!(positive_hit(&resolver, &question(QueryType::A)).is_some());
    assert!(resolver.negative_cache.get(&maila).is_some());
}

#[test]
fn aggregate_conflicts_preserve_authoritative_precedence_in_both_directions() {
    for (aggregate_type, members) in aggregate_families() {
        let concrete_type = members[0];
        let concrete_question = question(query_type_for_record(concrete_type));
        let aggregate_question = question(aggregate_type);

        let resolver = new_resolver();
        resolver.cache_positive_entries(
            1,
            &aggregate_positive(aggregate_type, members),
            &aggregate_question,
        );
        let lower_trust_nodata = negative(&concrete_question, RCode::Ok, false);
        resolver.cache_response_entries(
            1,
            &lower_trust_nodata,
            &concrete_question,
            &concrete_question,
            false,
        );
        assert!(positive_hit(&resolver, &aggregate_question).is_some());
        assert!(positive_hit(&resolver, &concrete_question).is_some());
        assert!(resolver.negative_cache.get(&concrete_question).is_none());

        let resolver = new_resolver();
        let authoritative_nodata = negative(&aggregate_question, RCode::Ok, true);
        resolver.cache_response_entries(
            1,
            &authoritative_nodata,
            &aggregate_question,
            &aggregate_question,
            true,
        );
        let lower_trust_positive = positive(
            &concrete_question,
            concrete_type,
            aggregate_rdata(concrete_type),
            false,
        );
        resolver.cache_positive_entries(1, &lower_trust_positive, &concrete_question);
        assert!(positive_hit(&resolver, &concrete_question).is_none());
        assert!(resolver.negative_cache.get(&aggregate_question).is_some());
    }
}

#[test]
fn accepted_positive_data_removes_matching_negative_data() {
    let resolver = new_resolver();
    let a = question(QueryType::A);
    let txt = question(QueryType::TXT);
    let nx = negative(&a, RCode::NameError, true);
    resolver.cache_response_entries(1, &nx, &a, &a, true);

    resolver.cache_positive_entries(1, &address(&a, true), &a);
    assert!(positive_hit(&resolver, &a).is_some());
    assert!(resolver.negative_cache.get(&a).is_none());
    assert!(resolver.negative_cache.get(&txt).is_none());

    let nodata = negative(&a, RCode::Ok, true);
    resolver.cache_response_entries(1, &nodata, &a, &a, true);
    resolver.cache_positive_entries(1, &address(&a, true), &a);
    assert!(resolver.negative_cache.get(&a).is_none());
}

#[test]
fn lower_trust_data_cannot_invalidate_authoritative_conflicts() {
    let a = question(QueryType::A);
    let cname_question = Question {
        qtype: QueryType::CNAME,
        ..a.clone()
    };

    for positive_authoritative in [false, true] {
        let resolver = new_resolver();
        resolver.cache_positive_entries(1, &address(&a, positive_authoritative), &a);
        let nx = negative(&a, RCode::NameError, false);
        resolver.cache_response_entries(1, &nx, &a, &a, false);
        assert!(positive_hit(&resolver, &a).is_some());
        assert!(resolver.negative_cache.get(&a).is_none());
    }

    let resolver = new_resolver();
    let nx = negative(&a, RCode::NameError, true);
    resolver.cache_response_entries(1, &nx, &a, &a, true);
    resolver.cache_positive_entries(1, &address(&a, false), &a);
    assert!(positive_hit(&resolver, &a).is_none());
    assert_eq!(
        resolver.negative_cache.get(&a).unwrap().headers.rcode,
        RCode::NameError
    );

    let resolver = new_resolver();
    resolver.cache_positive_entries(1, &address(&a, true), &a);
    resolver.cache_positive_entries(1, &cname(&a, false), &a);
    assert!(positive_hit(&resolver, &a).is_some());
    assert!(positive_hit(&resolver, &cname_question).is_none());

    let resolver = new_resolver();
    resolver.cache_positive_entries(1, &cname(&a, true), &a);
    resolver.cache_positive_entries(1, &address(&a, false), &a);
    assert!(positive_hit(&resolver, &a).is_none());
    assert!(positive_hit(&resolver, &cname_question).is_some());
}

#[test]
fn cname_and_ordinary_data_replace_each_other_and_cname_clears_nodata() {
    let resolver = new_resolver();
    let a = question(QueryType::A);
    let txt = question(QueryType::TXT);
    let cname_question = Question {
        qtype: QueryType::CNAME,
        ..a.clone()
    };

    resolver.cache_positive_entries(1, &address(&a, false), &a);
    resolver.cache_positive_entries(1, &cname(&a, false), &a);
    assert!(positive_hit(&resolver, &a).is_none());
    assert!(positive_hit(&resolver, &cname_question).is_some());

    resolver.cache_positive_entries(1, &address(&a, false), &a);
    assert!(positive_hit(&resolver, &a).is_some());
    assert!(positive_hit(&resolver, &cname_question).is_none());

    let nodata = negative(&txt, RCode::Ok, true);
    resolver.cache_response_entries(1, &nodata, &txt, &txt, true);
    resolver.cache_positive_entries(1, &cname(&a, true), &a);
    assert!(resolver.negative_cache.get(&txt).is_none());
}

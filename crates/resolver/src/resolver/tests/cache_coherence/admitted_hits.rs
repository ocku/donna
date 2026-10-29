use super::*;
use crate::{ResolutionCacheSource, ResolutionResult, ResolveError};

#[tokio::test]
async fn deferred_partial_alias_miss_preserves_the_original_eviction_choice() {
    let original = question(QueryType::A);
    let alias = Question {
        qtype: QueryType::CNAME,
        ..original.clone()
    };
    let sentinel = Question {
        qname: name(&["sentinel", "example"]),
        ..original.clone()
    };
    let newcomer = Question {
        qname: name(&["new", "example"]),
        ..original.clone()
    };
    for immediate in [false, true] {
        let resolver = Resolver::new(
            UnusedTransport,
            ResolverConfig {
                cache_capacity: 2,
                root_servers: vec!["127.0.0.1:53".parse().unwrap()],
                max_steps: 1,
                ..ResolverConfig::default()
            },
        );
        resolver.cache_positive_entries(1, &cname(&alias, true), &alias);
        resolver.cache_positive_entries(1, &address(&sentinel, true), &sentinel);
        for _ in 0..2 {
            assert!(resolver.cached_positive_response(&sentinel).is_some());
        }
        if immediate {
            assert!(resolver.try_resolve_cached(&original).unwrap().is_none());
            assert!(
                resolver
                    .resolve_with_cache_check(
                        original.clone(),
                        super::super::AlgorithmSignals::default(),
                        false,
                        false,
                    )
                    .await
                    .is_err()
            );
        } else {
            assert!(resolver.resolve(original.clone()).await.is_err());
        }
        resolver.cache_positive_entries(1, &address(&newcomer, true), &newcomer);
        // The alias and sentinel each received two hits. Exact (hits, slot)
        // eviction must still remove the older alias; a repeated preflight
        // lookup would give it a third hit and evict the sentinel instead.
        assert!(resolver.cached_positive_response(&alias).is_none());
        assert!(resolver.cached_positive_response(&sentinel).is_some());
        assert!(resolver.cached_positive_response(&newcomer).is_some());
    }
}

fn assert_warm_hit(result: &ResolutionResult, source: ResolutionCacheSource) {
    let stats = result.stats();
    assert_eq!(stats.final_cache_source(), Some(source));
    assert_eq!(stats.udp_transmissions(), 0);
    assert_eq!(stats.response_rounds(), 0);
    assert_eq!(stats.name_server_lookups(), 0);
    assert_eq!(stats.tcp_transitions(), 0);
    assert_eq!(stats.coalesced_leaders(), 0);
    assert_eq!(stats.coalesced_followers(), 0);
    assert!(!result.response().headers.ad);
}

fn assert_question(reply: &Message, expected: &Question) {
    assert_eq!(reply.questions.len(), 1);
    assert!(reply.questions[0].qname.eq_dns(&expected.qname));
    assert_eq!(reply.questions[0].qtype, expected.qtype);
    assert_eq!(reply.questions[0].qclass, expected.qclass);
}

#[tokio::test]
async fn unsigned_warm_negative_and_cname_hits_bypass_coalescing() {
    for rcode in [RCode::Ok, RCode::NameError] {
        for alias in [false, true] {
            let resolver = new_resolver();
            let original = question(QueryType::A);
            let terminal = if alias {
                Question {
                    qname: name(&["target", "example"]),
                    ..original.clone()
                }
            } else {
                original.clone()
            };
            let mut denial = negative(&terminal, rcode, true);
            // An upstream AD bit is never proof of local validation.
            denial.headers.ad = true;
            resolver.cache_response_entries(1, &denial, &terminal, &terminal, true);
            if alias {
                let alias_question = Question {
                    qtype: QueryType::CNAME,
                    ..original.clone()
                };
                let mut alias_reply = cname(&alias_question, true);
                alias_reply.headers.ad = true;
                resolver.cache_positive_entries(1, &alias_reply, &alias_question);
            }

            let plain = resolver.resolve(original.clone()).await.unwrap();
            let result = resolver.resolve_with_stats(original.clone()).await.unwrap();
            assert_warm_hit(&result, ResolutionCacheSource::Negative);
            assert_eq!(result.response().headers.rcode, rcode);
            assert_question(result.response(), &original);
            assert_eq!(result.response().answers.len(), usize::from(alias));
            assert_eq!(plain.answers.len(), result.response().answers.len());
            assert!(!plain.headers.ad);
            assert!(
                result
                    .response()
                    .authorities
                    .iter()
                    .any(|record| { record.rtype == RecordType::SOA && record.ttl <= 60 })
            );
        }
    }
}

#[tokio::test]
async fn unsigned_warm_cname_positive_hit_bypasses_coalescing() {
    let resolver = new_resolver();
    let original = question(QueryType::A);
    let terminal = Question {
        qname: name(&["target", "example"]),
        ..original.clone()
    };
    let alias_question = Question {
        qtype: QueryType::CNAME,
        ..original.clone()
    };
    let mut alias_reply = cname(&alias_question, true);
    alias_reply.headers.ad = true;
    resolver.cache_positive_entries(1, &alias_reply, &alias_question);
    let mut terminal_reply = address(&terminal, true);
    terminal_reply.headers.ad = true;
    resolver.cache_positive_entries(1, &terminal_reply, &terminal);

    let result = resolver.resolve_with_stats(original.clone()).await.unwrap();
    assert_warm_hit(&result, ResolutionCacheSource::Positive);
    assert_question(result.response(), &original);
    assert_eq!(result.response().answers.len(), 2);
    assert_eq!(result.response().answers[0].rtype, RecordType::CNAME);
    assert_eq!(result.response().answers[1].rtype, RecordType::A);
    assert!(!result.response().headers.aa);
}

#[tokio::test]
async fn unsigned_direct_positive_cache_hit_cannot_trust_upstream_ad() {
    let resolver = new_resolver();
    let question = question(QueryType::A);
    let mut reply = address(&question, true);
    reply.headers.ad = true;
    resolver.cache_positive_entries(1, &reply, &question);
    let result = resolver.resolve_with_stats(question).await.unwrap();
    assert_warm_hit(&result, ResolutionCacheSource::Positive);
}

#[test]
fn unsigned_cached_cname_traversal_retains_work_bounds_and_loop_detection() {
    let mut resolver = new_resolver();
    resolver.config.max_steps = 1;
    let original = question(QueryType::A);
    let terminal = Question {
        qname: name(&["target", "example"]),
        ..original.clone()
    };
    for owner in [&original, &terminal] {
        let alias_question = Question {
            qtype: QueryType::CNAME,
            ..owner.clone()
        };
        let target = if owner.qname.eq_dns(&terminal.qname) {
            name(&["last", "example"])
        } else {
            terminal.qname.clone()
        };
        let reply = positive(
            &alias_question,
            RecordType::CNAME,
            RData::CNAME(target),
            true,
        );
        resolver.cache_positive_entries(1, &reply, &alias_question);
    }
    assert!(matches!(
        resolver.cached_client_response(&original),
        Err(ResolveError::WorkLimitExceeded)
    ));
    resolver.config.max_steps = 4;
    let alias_question = Question {
        qtype: QueryType::CNAME,
        ..terminal
    };
    let reply = positive(
        &alias_question,
        RecordType::CNAME,
        RData::CNAME(original.qname.clone()),
        true,
    );
    resolver.cache_positive_entries(1, &reply, &alias_question);
    assert!(matches!(
        resolver.cached_client_response(&original),
        Err(ResolveError::CnameLoop)
    ));
}

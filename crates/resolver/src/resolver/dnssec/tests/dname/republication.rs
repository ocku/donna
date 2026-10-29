//! Reusing a typed cache proof must not repeatedly round away its lifetime.
use super::super::{
    fixtures::{resolver, signed_record_fixture},
    support::name,
};
use super::cache::network::Routed;
use dns::{ClassType, DnssecSecurityStatus, QClassType, QueryType, Question, RData, RecordType};
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

#[tokio::test]
async fn distinct_cached_dname_targets_preserve_origin_but_fresh_lower_ttl_replaces_it() {
    let (mut source, anchor, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    for rr in &mut source.answer.answers {
        rr.ttl = 60;
    }
    // Prepare all independently signed targets before acquiring the initial
    // DNAME, so fixture-key generation consumes none of its tested lifetime.
    let mut targets = Vec::new();
    let mut questions = Vec::new();
    for index in 0..12 {
        let host = format!("n{index}");
        let (target, _, _) = signed_record_fixture(
            false,
            name(&[&host, "new", "example"]),
            QueryType::A,
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, index + 1)),
        );
        targets.push(target.answer);
        questions.push(Question {
            qname: name(&[&host, "old", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        });
    }
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = resolver(
        Routed {
            source: Arc::new(Mutex::new(source.answer)),
            targets,
            dnskey: source.dnskey,
            requests: requests.clone(),
            servers: Arc::new(Mutex::new(Vec::new())),
        },
        anchor,
    );
    let first = resolver.resolve(questions[0].clone()).await.unwrap();
    assert!(first.headers.ad);
    let origin = resolver
        .select_cached_dname(&questions[0])
        .unwrap()
        .selection;
    let identity = origin.identity();
    let maximum_ttl = origin.ttl();
    let before = requests.lock().unwrap().len();
    for (index, question) in questions.iter().enumerate().skip(1) {
        let reply = resolver.resolve(question.clone()).await.unwrap();
        assert!(reply.headers.ad);
        assert!(reply.answers.iter().any(|rr| {
            matches!(rr.rdata, RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, index as u8 + 1))
        }));
        let current = resolver.select_cached_dname(question).unwrap().selection;
        assert!(
            current.matches_identity(&identity),
            "cached-origin proof was republished after target{index}"
        );
        assert!(current.is_live() && current.ttl() <= maximum_ttl);
    }
    {
        let observed = requests.lock().unwrap();
        assert_eq!(
            observed.len() - before,
            11,
            "one terminal acquisition per new owner"
        );
        assert!(observed[before..].iter().all(|q| {
            q.qtype == QueryType::A && q.qname.is_descendant_of(&name(&["new", "example"]))
        }));
    }

    // A new source-less packet with unchanged signed RDATA and a shorter TTL
    // is a distinct observation, not permission to keep the old cached bound.
    let mut fresh = first;
    fresh.headers.ad = false;
    for rr in &mut fresh.answers {
        rr.ttl = if rr.name.eq_dns(&name(&["old", "example"])) || rr.rtype == RecordType::CNAME {
            4
        } else {
            300
        };
    }
    let validation = resolver
        .validate_dnssec_response_with_deadline(&questions[0], &mut fresh, None)
        .await
        .unwrap();
    assert_eq!(validation.status, DnssecSecurityStatus::Secure);
    fresh.headers.ad = true;
    resolver
        .cache_validated_response_with_dnames_backend(&fresh, &questions[0], &validation)
        .await
        .unwrap();
    let replaced = resolver
        .select_cached_dname(&questions[0])
        .unwrap()
        .selection;
    assert!(
        !replaced.matches_identity(&identity),
        "fresh source-less lower TTL must replace prior proof"
    );
    assert!(replaced.ttl() <= 4);

    let lookup = Question {
        qname: name(&["old", "example"]),
        qtype: QueryType::DNAME,
        qclass: questions[0].qclass,
    };
    let stale = crate::resolver::cache::dname::traversal::CachedDnameSource {
        question: lookup.clone(),
        identity: origin.identity(),
    };
    // The original selected object remains strongly held above, so this
    // exercises a live Weak identity that no longer names the cache entry.
    for evicted in [false, true] {
        if evicted {
            resolver.positive_cache.remove_name(&lookup);
        }
        fresh.headers.ad = false;
        for rr in &mut fresh.answers {
            if rr.name.eq_dns(&lookup.qname) || rr.rtype == RecordType::CNAME {
                rr.ttl = 2;
            }
        }
        let validation = resolver
            .validate_dnssec_response_with_deadline(&questions[0], &mut fresh, None)
            .await
            .unwrap();
        assert_eq!(validation.status, DnssecSecurityStatus::Secure);
        fresh.headers.ad = true;
        resolver
            .cache_validated_response_with_sources_backend(
                &fresh,
                &questions[0],
                &validation,
                std::slice::from_ref(&stale),
            )
            .await
            .unwrap();
        let current = resolver
            .select_cached_dname(&questions[0])
            .unwrap()
            .selection;
        assert!(!current.matches_identity(&identity));
        assert!(current.is_live() && current.ttl() <= 2);
        assert!(
            resolver
                .cached_client_response(&questions[0])
                .unwrap()
                .is_some()
        );
    }
}

mod refresh;

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use dns::{QClassType, QueryType};

use super::*;

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn question(labels: &[&str], class: QClassType) -> Question {
    Question {
        qname: name(labels),
        qtype: QueryType::A,
        qclass: class,
    }
}

fn address(last_octet: u8) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(192, 0, 2, last_octet), 53))
}

fn referral(
    zone: DomainName,
    candidates: Vec<SocketAddr>,
    name_servers: Vec<DomainName>,
    address_ttl: Option<Duration>,
    ttl: Duration,
) -> Referral {
    Referral {
        zone,
        class: ClassType::IN,
        candidate_ttls: candidates
            .iter()
            .copied()
            .map(|address| (address, address_ttl.unwrap_or_default()))
            .collect(),
        candidates,
        trusted_glue: Vec::new(),
        name_servers,
        ttl,
    }
}

#[test]
fn returns_the_closest_case_insensitive_ancestor() {
    let cache = DelegationCache::new(4);
    let example = vec![address(1)];
    let child = vec![address(2)];
    cache.insert(
        &referral(
            name(&["Example"]),
            example,
            vec![name(&["ns", "example"])],
            Some(Duration::from_secs(60)),
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );
    cache.insert(
        &referral(
            name(&["Child", "EXAMPLE"]),
            child.clone(),
            vec![name(&["ns", "child", "example"])],
            Some(Duration::from_secs(60)),
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );

    let query = question(
        &["www", "child", "example"],
        QClassType::Class(ClassType::IN),
    );
    let cached = cache.get(&query).unwrap();
    assert!(cached.zone.eq_dns(&name(&["child", "example"])));
    assert_eq!(cached.candidates, child);
    let mut records = Vec::new();
    cache.append_referral_records(&query, &mut records);
    assert_eq!(records.len(), 1);
    assert!(records[0].name.eq_dns(&cached.zone));
    assert_eq!(records[0].class, ClassType::IN);
    assert_eq!(records[0].rtype, dns::RecordType::NS);
    assert!(records[0].ttl <= 60);
    assert_eq!(
        records[0].rdata,
        dns::RData::NS(name(&["ns", "child", "example"]))
    );
}

#[test]
fn ignores_non_matching_classes_and_uncacheable_delegations() {
    let cache = DelegationCache::new(2);
    let zone = name(&["example"]);
    let candidates = vec![address(1)];

    cache.insert(
        &referral(
            zone.clone(),
            candidates.clone(),
            vec![name(&["ns", "example"])],
            Some(Duration::from_secs(60)),
            Duration::ZERO,
        ),
        Duration::from_secs(60),
    );
    cache.insert(
        &referral(
            zone.clone(),
            Vec::new(),
            Vec::new(),
            None,
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );
    cache.insert(
        &referral(
            zone,
            candidates,
            vec![name(&["ns", "example"])],
            Some(Duration::from_secs(60)),
            Duration::from_secs(60),
        ),
        Duration::ZERO,
    );

    assert!(
        cache
            .get(&question(
                &["www", "example"],
                QClassType::Class(ClassType::IN),
            ))
            .is_none()
    );
    assert!(
        cache
            .get(&question(&["www", "example"], QClassType::ANY))
            .is_none()
    );
}

#[test]
fn replaces_same_zone_regardless_of_case() {
    let cache = DelegationCache::new(2);
    let replacement = vec![address(2)];
    cache.insert(
        &referral(
            name(&["Example"]),
            vec![address(1)],
            vec![name(&["ns1", "example"])],
            Some(Duration::from_secs(60)),
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );
    cache.insert(
        &referral(
            name(&["example"]),
            replacement.clone(),
            vec![name(&["ns2", "example"])],
            Some(Duration::from_secs(60)),
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );

    let cached = cache
        .get(&question(
            &["www", "EXAMPLE"],
            QClassType::Class(ClassType::IN),
        ))
        .unwrap();
    assert!(cached.zone.eq_dns(&name(&["example"])));
    assert_eq!(cached.candidates, replacement);
    assert_eq!(cache.entries.lock().unwrap().len(), 1);
}

#[test]
fn evicts_the_least_used_entry_at_capacity() {
    let cache = DelegationCache::new(2);
    cache.insert(
        &referral(
            name(&["one", "test"]),
            vec![address(1)],
            vec![name(&["ns", "one", "test"])],
            Some(Duration::from_secs(60)),
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );
    cache.insert(
        &referral(
            name(&["two", "test"]),
            vec![address(2)],
            vec![name(&["ns", "two", "test"])],
            Some(Duration::from_secs(60)),
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );
    assert!(
        cache
            .get(&question(
                &["www", "one", "test"],
                QClassType::Class(ClassType::IN),
            ))
            .is_some()
    );

    let third = vec![address(3)];
    cache.insert(
        &referral(
            name(&["three", "test"]),
            third.clone(),
            vec![name(&["ns", "three", "test"])],
            Some(Duration::from_secs(60)),
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );

    assert!(
        cache
            .get(&question(
                &["www", "one", "test"],
                QClassType::Class(ClassType::IN),
            ))
            .is_some()
    );
    assert!(
        cache
            .get(&question(
                &["www", "two", "test"],
                QClassType::Class(ClassType::IN),
            ))
            .is_none()
    );
    let cached = cache
        .get(&question(
            &["www", "three", "test"],
            QClassType::Class(ClassType::IN),
        ))
        .unwrap();
    assert_eq!(cached.candidates, third);
}

#[test]
fn retains_the_full_ns_set_after_glue_expires() {
    let cache = DelegationCache::new(1);
    let addressed = name(&["ns1", "example"]);
    let unaddressed = name(&["ns", "provider"]);
    cache.insert(
        &referral(
            name(&["example"]),
            vec![address(1)],
            vec![addressed.clone(), unaddressed.clone()],
            Some(Duration::ZERO),
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );

    let cached = cache
        .get(&question(
            &["www", "example"],
            QClassType::Class(ClassType::IN),
        ))
        .unwrap();

    assert!(cached.candidates.is_empty());
    assert_eq!(cached.name_servers, [addressed, unaddressed]);
}

#[test]
fn expires_glue_addresses_independently() {
    let cache = DelegationCache::new(1);
    let short = address(1);
    let long = address(2);
    let mut referral = referral(
        name(&["example"]),
        vec![short, long],
        vec![name(&["ns1", "example"]), name(&["ns2", "example"])],
        Some(Duration::from_secs(60)),
        Duration::from_secs(60),
    );
    referral.candidate_ttls = vec![(short, Duration::ZERO), (long, Duration::from_secs(60))];
    cache.insert(&referral, Duration::from_secs(60));

    let cached = cache
        .get(&question(
            &["www", "example"],
            QClassType::Class(ClassType::IN),
        ))
        .unwrap();

    assert_eq!(cached.candidates, [long]);
}

#[test]
fn does_not_admit_a_referral_with_only_provisional_candidates() {
    let cache = DelegationCache::new(1);
    let zone = name(&["com"]);
    let mut referral = referral(
        zone,
        vec![address(1)],
        vec![name(&["a", "gtld-servers", "net"])],
        Some(Duration::from_secs(60)),
        Duration::from_secs(60),
    );
    referral.candidate_ttls.clear();

    cache.insert(&referral, Duration::from_secs(60));

    assert!(
        cache
            .get(&question(
                &["www", "example", "com"],
                QClassType::Class(ClassType::IN),
            ))
            .is_none()
    );
}

#[test]
fn ds_queries_skip_the_cached_child_apex_but_keep_ancestor_delegations() {
    let cache = DelegationCache::new(3);
    for (labels, last_octet) in [(&["example"][..], 1), (&["child", "example"][..], 2)] {
        cache.insert(
            &referral(
                name(labels),
                vec![address(last_octet)],
                vec![name(&["ns", "example"])],
                Some(Duration::from_secs(60)),
                Duration::from_secs(60),
            ),
            Duration::from_secs(60),
        );
    }
    let mut ds = question(&["ChIlD", "EXAMPLE"], QClassType::Class(ClassType::IN));
    ds.qtype = QueryType::DS;
    assert_eq!(cache.get(&ds).unwrap().candidates, [address(1)]);
    ds.qname = name(&["sub", "child", "example"]);
    assert_eq!(cache.get(&ds).unwrap().candidates, [address(2)]);
    ds.qname = name(&["example"]);
    assert!(cache.get(&ds).is_none());
    ds.qname = DomainName::root();
    assert!(cache.get(&ds).is_none());
}

#[test]
fn inline_referral_projection_spills_without_truncating_or_repeating_a_touch() {
    let cache = DelegationCache::new(1);
    let names: Vec<_> = (0..9)
        .map(|index| name(&[&format!("ns-{index}"), "example"]))
        .collect();
    cache.insert(
        &referral(
            name(&["example"]),
            vec![],
            names.clone(),
            None,
            Duration::from_secs(60),
        ),
        Duration::from_secs(60),
    );
    let q = question(&["owner", "example"], QClassType::Class(ClassType::IN));
    let mut records = smallvec::SmallVec::<[ResourceRecord; 4]>::new();
    cache.append_referral_records(&q, &mut records);
    assert!(records.spilled());
    assert_eq!(records.len(), names.len());
    for (record, target) in records.iter().zip(names) {
        assert_eq!(record.rdata, RData::NS(target));
        assert_eq!(record.name, name(&["example"]));
        assert_eq!(record.class, ClassType::IN);
        assert!(record.ttl <= 60);
    }
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 1);
}

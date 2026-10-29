use super::*;
use crate::cache::codec::{Reader, Writer};

fn zone() -> DomainName {
    DomainName::from_dotted("example.test.").unwrap()
}
fn q(owner: &str) -> Question {
    Question {
        qname: DomainName::from_dotted(owner).unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}
fn seed(cache: &DelegationCache, ttl: Duration) {
    let address = "192.0.2.1:53".parse().unwrap();
    cache.insert(
        &Referral {
            zone: zone(),
            class: ClassType::IN,
            candidates: vec![address],
            candidate_ttls: vec![(address, ttl)],
            trusted_glue: vec![],
            name_servers: vec![DomainName::from_dotted("ns.example.test.").unwrap()],
            ttl,
        },
        ttl,
    );
}
fn expire(cache: &DelegationCache, ns: bool, lease: bool) {
    let mut entries = cache.entries.lock().unwrap();
    let past = Instant::now() - Duration::from_millis(1);
    for index in 0..entries.len() {
        entries.modify(index, |e| {
            if ns {
                e.expires_at = past;
            }
            if lease {
                for r in e.refresh.iter_mut().flatten() {
                    r.expires_at = past;
                }
            }
        });
    }
}
fn lease(cache: &DelegationCache) -> RefreshLease {
    cache
        .entries
        .lock()
        .unwrap()
        .values
        .iter()
        .find(|e| e.key.class == ClassType::IN && e.zone.eq_dns(&zone()))
        .unwrap()
        .refresh[0]
        .unwrap()
}
fn round_trip(cache: &DelegationCache) -> DelegationCache {
    let secret = [7; 32];
    let mut out = Writer::new(1024 * 1024, &secret, b"refresh-tests").unwrap();
    cache.encode_entries(&mut out).unwrap();
    let restored = DelegationCache::for_engine(cache.capacity);
    let mut input = Reader::new(&out.bytes, &secret, b"refresh-tests").unwrap();
    restored.decode_entries(&mut input).unwrap();
    assert!(input.finished());
    restored
}

#[test]
fn claims_scope_class_cd_and_do_not_extend_live_deadlines() {
    let cache = DelegationCache::new(4);
    seed(&cache, Duration::from_secs(60));
    let token = cache
        .claim_refresh(&zone(), ClassType::IN, false, Duration::ZERO)
        .unwrap();
    let first = lease(&cache);
    assert!(first.expires_at > Instant::now());
    assert!(
        cache
            .claim_refresh(&zone(), ClassType::IN, false, Duration::from_secs(300))
            .is_none()
    );
    assert_eq!(lease(&cache).expires_at, first.expires_at);
    assert!(
        cache
            .claim_refresh(&zone(), ClassType::IN, true, Duration::from_secs(1))
            .is_some()
    );
    assert!(
        cache
            .claim_refresh(&zone(), ClassType::CH, false, Duration::from_secs(1))
            .is_some()
    );
    assert!(cache.start_refresh(&zone(), ClassType::IN, false, token, Duration::from_secs(1)));
    cache.finish_refresh_failure(&zone(), ClassType::IN, false, token, Duration::from_secs(1));
    let failed = lease(&cache);
    cache.finish_refresh_failure(
        &zone(),
        ClassType::IN,
        false,
        token,
        Duration::from_secs(300),
    );
    assert_eq!(lease(&cache).expires_at, failed.expires_at);
    // Fresh data still routes to the child, and neither read nor reinsert renews failure metadata.
    assert!(cache.get(&q("new.example.test.")).is_some());
    seed(&cache, Duration::from_secs(60));
    assert_eq!(lease(&cache).expires_at, failed.expires_at);
}

#[test]
fn expired_old_owner_cannot_start_or_finish_over_a_new_owner() {
    let cache = DelegationCache::new(2);
    seed(&cache, Duration::from_secs(60));
    let a = cache
        .claim_refresh(&zone(), ClassType::IN, false, Duration::from_secs(1))
        .unwrap();
    expire(&cache, false, true);
    let b = cache
        .claim_refresh(&zone(), ClassType::IN, false, Duration::from_secs(1))
        .unwrap();
    assert_ne!(a, b);
    assert!(!cache.start_refresh(&zone(), ClassType::IN, false, a, Duration::from_secs(1)));
    cache.finish_refresh_failure(&zone(), ClassType::IN, false, a, Duration::from_secs(1));
    assert!(!lease(&cache).failed);
    assert!(cache.start_refresh(&zone(), ClassType::IN, false, b, Duration::from_secs(1)));
    cache.finish_refresh_failure(&zone(), ClassType::IN, false, b, Duration::from_secs(1));
    assert!(lease(&cache).failed);
}

#[test]
fn expired_or_zero_ttl_routes_leave_only_scoped_proven_failure_tombstones() {
    for ttl in [Duration::ZERO, Duration::from_secs(60)] {
        let cache = DelegationCache::new(2);
        seed(&cache, ttl);
        let token = cache
            .claim_refresh(&zone(), ClassType::IN, false, Duration::from_secs(1))
            .unwrap();
        // An in-flight/cancelled owner is never evidence that the zone is unavailable.
        expire(&cache, true, false);
        assert!(cache.get(&q("fresh.example.test.")).is_none());
        assert!(!cache.failed_without_routes(&q("fresh.example.test."), false));
        assert!(cache.start_refresh(&zone(), ClassType::IN, false, token, Duration::from_secs(1)));
        cache.finish_refresh_failure(&zone(), ClassType::IN, false, token, Duration::from_secs(1));
        assert!(cache.failed_without_routes(&q("fresh.example.test."), false));
        assert!(!cache.failed_without_routes(&q("fresh.example.test."), true));
        assert!(!cache.failed_without_routes(&q("sibling.test."), false));
        let mut ds = q("example.test.");
        ds.qtype = QueryType::DS;
        assert!(!cache.failed_without_routes(&ds, false));
        let mut records = Vec::new();
        cache.append_referral_records(&q("fresh.example.test."), &mut records);
        assert!(records.is_empty(), "expired NS must never be exposed");
        let original_deadline = lease(&cache).expires_at;
        let restored = round_trip(&cache);
        assert!(restored.failed_without_routes(&q("fresh.example.test."), false));
        assert!(lease(&restored).expires_at <= original_deadline + Duration::from_millis(10));
        expire(&restored, true, true);
        let expired_again = round_trip(&restored);
        assert!(!expired_again.failed_without_routes(&q("fresh.example.test."), false));
    }
}

#[test]
fn successful_child_data_prevents_late_failure_resurrection_and_retention_is_bounded() {
    let cache = DelegationCache::new(2);
    let token = cache
        .claim_refresh(&zone(), ClassType::IN, false, Duration::from_secs(500))
        .unwrap();
    assert!(
        lease(&cache)
            .expires_at
            .saturating_duration_since(Instant::now())
            <= Duration::from_secs(300)
    );
    cache.refresh_succeeded(&zone(), ClassType::IN, false, Some(token), true);
    cache.finish_refresh_failure(&zone(), ClassType::IN, false, token, Duration::from_secs(1));
    assert!(!cache.failed_without_routes(&q("fresh.example.test."), false));
    for index in 0..8 {
        let name = DomainName::from_dotted(&format!("zone{index}.test.")).unwrap();
        cache.claim_refresh(&name, ClassType::IN, false, Duration::from_secs(1));
    }
    assert!(cache.entries.lock().unwrap().len() <= 2);
    let disabled = DelegationCache::new(0);
    disabled.claim_refresh(&zone(), ClassType::IN, false, Duration::from_secs(1));
    assert!(disabled.entries.lock().unwrap().values.is_empty());
}

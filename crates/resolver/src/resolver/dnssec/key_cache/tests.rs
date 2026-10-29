use super::*;

fn key() -> ZoneKey {
    let keys = super::super::tests::trusted_keys();
    ZoneKey {
        zone: keys.zone().clone(),
        class: keys.class(),
        anchor: keys.zone().clone(),
    }
}

#[test]
fn hits_consume_the_original_chain_lifetime_without_renewal() {
    let cache = AuthenticatedZoneCache::new(2);
    let now = ValidationTime::now();
    let started = ValidationTime {
        instant: now.instant - Duration::from_secs(5),
        unix: now.unix.wrapping_sub(5),
    };
    cache.insert(
        key(),
        super::super::tests::trusted_keys(),
        10,
        started,
        Duration::from_secs(100),
    );
    for age in [6, 7, 9] {
        let at = ValidationTime {
            instant: started.instant + Duration::from_secs(age),
            unix: started.unix.wrapping_add(age as u32),
        };
        assert_eq!(cache.get(&key(), at).unwrap().ttl, 10 - age as u32);
    }
    let expiry = ValidationTime {
        instant: started.instant + Duration::from_secs(10),
        unix: started.unix.wrapping_add(10),
    };
    assert!(cache.get(&key(), expiry).is_none());
}

#[test]
fn slow_acquisition_zero_ttl_and_capacity_zero_cannot_admit_trust() {
    let keys = super::super::tests::trusted_keys();
    let cache = AuthenticatedZoneCache::new(2);
    let now = ValidationTime::now();
    let old = ValidationTime {
        instant: now.instant - Duration::from_secs(12),
        unix: now.unix.wrapping_sub(12),
    };
    cache.insert(key(), Arc::clone(&keys), 10, old, Duration::from_secs(100));
    assert!(cache.get(&key(), now).is_none());
    cache.insert(key(), Arc::clone(&keys), 10, now, Duration::from_secs(100));
    cache.insert(key(), Arc::clone(&keys), 0, now, Duration::from_secs(100));
    assert!(cache.get(&key(), now).is_none());
    let disabled = AuthenticatedZoneCache::new(0);
    disabled.insert(key(), keys, 100, now, Duration::from_secs(100));
    assert!(disabled.get(&key(), now).is_none());
    assert!(disabled.gate(&key()).is_none());
}

#[test]
fn clock_guards_accept_serial_wrap_and_reject_backward_forward_and_monotonic_expiry() {
    let started = ValidationTime {
        instant: Instant::now(),
        unix: u32::MAX - 2,
    };
    let entry = Entry {
        hash: 0,
        owner: packed_key(&key().zone),
        key: key(),
        keys: super::super::tests::trusted_keys(),
        started,
        lifetime: 10,
        expires_at: started.instant + Duration::from_secs(10),
        refresh_after: started.instant,
        signature_expiration: started.unix.wrapping_add(1000),
        hits: 0,
    };
    let at = |seconds, unix| ValidationTime {
        instant: started.instant + Duration::from_secs(seconds),
        unix,
    };
    assert_eq!(entry.remaining(at(5, 2)), Some(5));
    assert!(
        entry
            .remaining(at(1, started.unix.wrapping_sub(1)))
            .is_none()
    );
    assert!(entry.remaining(at(1, 5)).is_none());
    assert!(entry.remaining(at(11, 7)).is_none());
}

#[test]
fn cache_policy_bounds_class_anchor_capacity_and_ttl() {
    let cache = AuthenticatedZoneCache::new(1);
    let now = ValidationTime::now();
    cache.insert(
        key(),
        super::super::tests::trusted_keys(),
        100,
        now,
        Duration::from_secs(3),
    );
    let mut different = key();
    different.class = ClassType::CH;
    assert!(cache.get(&different, now).is_none());
    different = key();
    different.anchor = DomainName::root();
    assert!(cache.get(&different, now).is_none());
    let future = ValidationTime {
        instant: now.instant + Duration::from_secs(4),
        unix: now.unix.wrapping_add(4),
    };
    assert!(cache.get(&key(), future).is_none());
    for index in 0..10 {
        let mut next = key();
        if index % 2 == 0 {
            next.anchor = DomainName::root();
        }
        cache.insert(
            next.clone(),
            super::super::tests::trusted_keys(),
            100,
            now,
            Duration::from_secs(100),
        );
        assert_eq!(cache.entries.lock().unwrap().len(), 1);
        assert!(cache.get(&next, now).is_some());
        let mut old = next;
        old.anchor = if index % 2 == 0 {
            key().anchor
        } else {
            DomainName::root()
        };
        assert!(cache.get(&old, now).is_none());
    }
}

#[test]
fn refresh_cooldown_survives_replacement_and_gates_are_bounded() {
    let cache = AuthenticatedZoneCache::new(1);
    let keys = super::super::tests::trusted_keys();
    let now = ValidationTime::now();
    cache.insert(key(), Arc::clone(&keys), 100, now, Duration::from_secs(100));
    assert!(cache.allow_refresh(&key(), &keys, ValidationTime::now()));
    cache.insert(key(), Arc::clone(&keys), 100, now, Duration::from_secs(100));
    assert!(!cache.allow_refresh(&key(), &keys, ValidationTime::now()));
    let first = cache.gate(&key()).unwrap();
    assert!(Arc::ptr_eq(&first, &cache.gate(&key()).unwrap()));
    let mut other = key();
    other.zone = DomainName::root();
    assert!(cache.gate(&other).is_none());
    drop(first);
    assert!(cache.gate(&other).is_some());
}

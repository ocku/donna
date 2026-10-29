use super::*;
use dns::{ClassType, DomainName, QClassType, QueryType};

impl FailureCache {
    /// Inspect policy timing without modifying cache state or deadlines.
    pub(crate) fn timing_for_test(
        &self,
        question: &Question,
        checking_disabled: bool,
    ) -> Option<(Duration, Instant)> {
        let entries = self.entries.lock().unwrap();
        let key = Key::new(question, checking_disabled);
        let hash = entries.hash_key(&key);
        entries.find(hash, |entry| entry.key == key).map(|index| {
            let entry = &entries.values[index];
            (entry.interval, entry.suppress_until)
        })
    }
}

fn question() -> Question {
    Question {
        qname: DomainName::from_dotted("Example.TEST.").unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

#[test]
fn failure_cache_separates_class_type_cd_and_matches_case() {
    let cache = FailureCache::new(4);
    let question = question();
    cache.insert(
        &question,
        false,
        FailureKind::Server,
        Duration::from_secs(1),
    );
    let mut other = question.clone();
    other.qname = DomainName::from_dotted("example.test.").unwrap();
    assert!(cache.get(&other, false).is_some());
    assert!(cache.get(&other, true).is_none());
    other.qtype = QueryType::AAAA;
    assert!(cache.get(&other, false).is_none());
    other.qtype = QueryType::A;
    other.qclass = QClassType::Class(ClassType::CH);
    assert!(cache.get(&other, false).is_none());
}

#[test]
fn failure_lifetime_is_bounded_and_repeated_hits_do_not_extend_it() {
    let cache = FailureCache::new(4);
    let question = question();
    let before = Instant::now();
    cache.insert(&question, false, FailureKind::Server, Duration::ZERO);
    let expiry = cache.entries.lock().unwrap().values[0].suppress_until;
    assert!(expiry >= before + Duration::from_secs(1));
    cache.insert(
        &question,
        false,
        FailureKind::Server,
        Duration::from_secs(300),
    );
    assert_eq!(
        cache.entries.lock().unwrap().values[0].suppress_until,
        expiry
    );
    let mut other = question;
    other.qtype = QueryType::AAAA;
    cache.insert(&other, false, FailureKind::Server, Duration::MAX);
    let entries = cache.entries.lock().unwrap();
    assert!(entries.values[1].suppress_until <= Instant::now() + Duration::from_secs(300));
}

#[test]
fn expired_failures_are_removed_and_capacity_zero_is_explicit() {
    let cache = FailureCache::new(1);
    let question = question();
    cache.insert(
        &question,
        false,
        FailureKind::Server,
        Duration::from_secs(1),
    );
    cache.entries.lock().unwrap().modify(0, |entry| {
        entry.suppress_until = Instant::now();
        entry.history_until = entry.suppress_until + Duration::from_secs(300);
    });
    assert!(cache.get(&question, false).is_none());
    let disabled = FailureCache::new(0);
    disabled.insert(
        &question,
        false,
        FailureKind::Server,
        Duration::from_secs(1),
    );
    assert!(disabled.get(&question, false).is_none());
}

#[test]
fn repeated_failures_back_off_are_bounded_and_success_resets_history() {
    let cache = FailureCache::new(1);
    let q = question();
    cache.insert(&q, false, FailureKind::Server, Duration::from_secs(1));
    for seconds in [2, 4, 8, 16, 32, 64, 128, 256, 300, 300] {
        let expected = Duration::from_secs(seconds);
        cache.entries.lock().unwrap().modify(0, |entry| {
            entry.suppress_until = Instant::now();
            entry.history_until = entry.suppress_until + Duration::from_secs(300);
        });
        assert!(cache.get(&q, false).is_none());
        let before = Instant::now();
        cache.insert(&q, false, FailureKind::Server, Duration::from_secs(1));
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.values[0].interval, expected);
        assert!(entries.values[0].suppress_until >= before + expected);
        assert!(entries.values[0].suppress_until <= Instant::now() + expected);
    }
    // A concurrent success does not erase an active failure.
    cache.clear_expired(&q, false);
    assert!(cache.get(&q, false).is_some());
    cache.entries.lock().unwrap().modify(0, |entry| {
        entry.suppress_until = Instant::now();
        entry.history_until = entry.suppress_until + Duration::from_secs(300);
    });
    cache.clear_expired(&q, false);
    cache.insert(&q, false, FailureKind::Server, Duration::from_secs(1));
    assert_eq!(
        cache.entries.lock().unwrap().values[0].interval,
        Duration::from_secs(1)
    );
    let mut other = q.clone();
    other.qtype = QueryType::AAAA;
    cache.insert(&other, false, FailureKind::Server, Duration::from_secs(1));
    assert!(cache.get(&q, false).is_none());
    assert!(cache.get(&other, false).is_some());
}

#[test]
fn entry_codec_retains_expired_history_for_next_failure() {
    use crate::cache::codec::{Reader, Writer};
    let q = question();
    let cache = FailureCache::new(1);
    cache.insert(&q, false, FailureKind::Server, Duration::from_secs(1));
    cache.entries.lock().unwrap().modify(0, |entry| {
        entry.suppress_until = Instant::now();
        entry.history_until = entry.suppress_until + Duration::from_secs(300);
    });
    let secret = [42; 32];
    let mut writer = Writer::new(4096, &secret, b"failure-policy").unwrap();
    cache.encode_entries(&mut writer).unwrap();
    let restored = FailureCache::for_engine(1);
    restored
        .decode_entries(&mut Reader::new(&writer.bytes, &secret, b"failure-policy").unwrap())
        .unwrap();
    assert!(restored.get(&q, false).is_none());
    restored.insert(&q, false, FailureKind::Server, Duration::from_secs(1));
    assert_eq!(
        restored.entries.lock().unwrap().values[0].interval,
        Duration::from_secs(2)
    );
}

#[test]
fn concurrent_failure_is_not_erased_and_history_eventually_expires() {
    let cache = FailureCache::new(1);
    let q = question();
    cache.insert(&q, false, FailureKind::Server, Duration::from_secs(1));
    // A concurrent success must not erase a failure that another lookup just
    // recorded. Cached positive answers can bypass the later reset as well.
    cache.clear_expired(&q, false);
    assert!(cache.get(&q, false).is_some());
    cache.entries.lock().unwrap().modify(0, |entry| {
        entry.suppress_until = Instant::now() - Duration::from_secs(301);
        entry.history_until = Instant::now() - Duration::from_secs(1);
    });
    cache.insert(&q, false, FailureKind::Server, Duration::from_secs(1));
    assert_eq!(
        cache.entries.lock().unwrap().values[0].interval,
        Duration::from_secs(1)
    );
}

#[test]
fn local_resource_and_backend_errors_are_not_resolution_failures() {
    for error in [
        ResolveError::DelegationRefreshInProgress,
        ResolveError::CachedDelegationFailure,
        ResolveError::CachedNameServerFailure,
        ResolveError::UnsupportedQuestion,
        ResolveError::WorkLimitExceeded,
        ResolveError::CacheBackend(std::io::Error::other("unavailable backend")),
        ResolveError::Transport(transport::TransportError::Io(
            std::io::ErrorKind::OutOfMemory.into(),
        )),
    ] {
        assert!(FailureKind::from_error(&error).is_none());
    }
    assert!(FailureKind::from_error(&ResolveError::TemporaryServerFailure).is_some());
}

#[test]
fn entry_codec_preserves_failure_deadline_without_resurrection() {
    use crate::cache::codec::{Reader, Writer};
    let question = question();
    let cache = FailureCache::new(1);
    cache.insert(&question, true, FailureKind::Server, Duration::from_secs(5));
    let expiry = cache.entries.lock().unwrap().values[0].suppress_until;
    let secret = [42; 32];
    let mut writer = Writer::new(4096, &secret, b"failure-policy").unwrap();
    cache.encode_entries(&mut writer).unwrap();
    let restored = FailureCache::for_engine(1);
    restored
        .decode_entries(&mut Reader::new(&writer.bytes, &secret, b"failure-policy").unwrap())
        .unwrap();
    let reconstructed = restored.entries.lock().unwrap().values[0].suppress_until;
    assert!(reconstructed <= expiry + Duration::from_millis(10));
    assert!(restored.get(&question, true).is_some());
    cache.entries.lock().unwrap().modify(0, |entry| {
        entry.suppress_until = Instant::now();
        entry.history_until = entry.suppress_until + Duration::from_secs(300);
    });
    let mut writer = Writer::new(4096, &secret, b"failure-policy").unwrap();
    cache.encode_entries(&mut writer).unwrap();
    let restored = FailureCache::for_engine(1);
    restored
        .decode_entries(&mut Reader::new(&writer.bytes, &secret, b"failure-policy").unwrap())
        .unwrap();
    assert!(restored.get(&question, true).is_none());
}

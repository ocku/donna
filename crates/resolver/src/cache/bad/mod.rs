use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use dns::Question;

use crate::{cache::entries::CacheEntries, cache::store::CacheEntry, name::packed_key};

const ADMISSION_FAILURES: u8 = 2;
mod codec;

pub(crate) struct BadCache {
    capacity: usize,
    entries: Mutex<CacheEntries<Entry>>,
}

#[derive(Eq, Hash, PartialEq)]
struct Key {
    qname: Box<[u8]>,
    qtype: u16,
    qclass: u16,
}

struct Entry {
    key: Key,
    hash: u64,
    failures: u8,
    expires_at: Instant,
}

impl CacheEntry for Entry {
    fn engine_key(&self) -> Option<crate::CacheEntryKey> {
        Some(crate::CacheEntryKey {
            family: crate::CacheEntryFamily {
                category: crate::CacheCategory::Bad,
                owner: self.key.qname.to_vec(),
                class: self.key.qclass,
            },
            discriminator: self.key.qtype.to_be_bytes().to_vec(),
        })
    }

    fn hash(&self) -> u64 {
        self.hash
    }
    fn owner(&self) -> &[u8] {
        &self.key.qname
    }
    fn expires_at(&self) -> Instant {
        self.expires_at
    }
    fn hits(&self) -> u32 {
        0
    }
    fn set_hits(&mut self, _: u32) {}
}

impl Key {
    fn new(question: &Question) -> Self {
        Self {
            qname: packed_key(&question.qname),
            qtype: question.qtype.value(),
            qclass: question.qclass.value(),
        }
    }
}

impl BadCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(CacheEntries::with_capacity(capacity)),
        }
    }

    pub(crate) fn contains(&self, question: &Question) -> bool {
        if self.capacity == 0 {
            return false;
        }
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let key = Key::new(question);
        let hash = entries.hash_key(&key);
        let Some(index) = entries.find(hash, |entry| entry.key == key) else {
            return false;
        };
        if entries.values[index].expires_at <= now {
            entries.remove(index);
            return false;
        }
        entries.note_access(index);
        entries.values[index].failures >= ADMISSION_FAILURES
    }

    pub(crate) fn record_failure(&self, question: &Question, ttl: Duration) {
        if self.capacity == 0 || ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let expires_at = now
            .checked_add(ttl.min(Duration::from_secs(300)))
            .unwrap_or(now);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.remove_expired(now);
        let key = Key::new(question);
        let hash = entries.hash_key(&key);
        let mut failures = 1;
        if let Some(index) = entries.find(hash, |entry| entry.key == key) {
            if entries.values[index].expires_at > now {
                failures = entries.values[index].failures.saturating_add(1);
            }
            entries.remove(index);
        }
        // Keep BAD's existing earliest-deadline eviction policy.
        if entries.len() == self.capacity {
            entries.remove_earliest();
        }
        entries.insert(
            Entry {
                key,
                hash,
                failures,
                expires_at,
            },
            self.capacity,
            now,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dns::{ClassType, DomainName, QClassType, QueryType};

    use super::*;

    fn question() -> Question {
        Question {
            qname: DomainName::from_labels(vec![b"Example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }
    }

    #[test]
    fn admits_only_repeated_failures_and_matches_names_case_insensitively() {
        let cache = BadCache::new(1);
        let question = question();
        cache.record_failure(&question, Duration::from_secs(30));
        assert!(!cache.contains(&question));
        cache.record_failure(&question, Duration::from_secs(30));

        let mut lowercase = question;
        lowercase.qname = DomainName::from_labels(vec![b"example".to_vec()]).unwrap();
        assert!(cache.contains(&lowercase));
    }

    #[test]
    fn zero_capacity_disables_the_cache() {
        let cache = BadCache::new(0);
        let question = question();
        cache.record_failure(&question, Duration::from_secs(30));
        cache.record_failure(&question, Duration::from_secs(30));
        assert!(!cache.contains(&question));
    }
}

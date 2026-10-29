use std::time::Duration;

use super::*;

struct Entry {
    key: u64,
    owner: Box<[u8]>,
    hash: u64,
    expiry: Instant,
    hits: u32,
}

impl CacheEntry for Entry {
    fn hash(&self) -> u64 {
        self.hash
    }
    fn owner(&self) -> &[u8] {
        &self.owner
    }
    fn expires_at(&self) -> Instant {
        self.expiry
    }
    fn hits(&self) -> u32 {
        self.hits
    }
    fn set_hits(&mut self, hits: u32) {
        self.hits = hits;
    }
}

fn entry(key: u64, expiry: Instant) -> Entry {
    Entry {
        key,
        owner: (key % 3).to_be_bytes().into(),
        hash: 42,
        expiry,
        hits: 0,
    }
}

fn consistent(store: &CacheStore<Entry>) {
    assert_eq!(store.expiration.len(), store.len());
    assert_eq!(store.popularity.len(), store.len());
    assert_eq!(
        store.by_hash.values().map(Vec::len).sum::<usize>(),
        store.len()
    );
    assert_eq!(
        store.by_owner.values().map(Vec::len).sum::<usize>(),
        store.len()
    );
    assert!(store.by_hash.values().all(|bucket| !bucket.is_empty()));
    assert!(store.by_owner.values().all(|bucket| !bucket.is_empty()));
    for (index, entry) in store.values.iter().enumerate() {
        assert!(store.expiration.contains(&(entry.expiry, index)));
        assert!(store.popularity.contains(&(entry.hits, index)));
        assert_eq!(
            store.find(entry.hash, |candidate| candidate.key == entry.key),
            Some(index)
        );
        assert!(store.by_owner.get(entry.owner()).unwrap().contains(&index));
    }
}

#[test]
fn collisions_swap_removals_and_replacements_keep_every_index_bounded() {
    let now = Instant::now();
    let expiry = now + Duration::from_secs(100);
    let mut store = CacheStore::with_capacity(7);
    for key in 0..500 {
        if let Some(index) = store.find(42, |entry: &Entry| entry.key == key % 5) {
            store.remove(index);
        }
        store.insert(entry(key, expiry), 7, now);
        for index in 0..store.len() {
            store.touch(index);
        }
        consistent(&store);
        assert!(store.len() <= 7);
        assert!(store.find(42, |entry| entry.key == u64::MAX).is_none());
    }
    store.remove_indices(vec![0, 2, 2, 4]);
    consistent(&store);
    while store.len() != 0 {
        store.remove(store.len() / 2);
        consistent(&store);
    }
    assert!(store.by_hash.is_empty());
    assert!(store.by_owner.is_empty());
}

#[test]
fn eviction_keeps_the_hot_entry_and_prefers_expired_data() {
    let now = Instant::now();
    let mut store = CacheStore::with_capacity(2);
    store.insert(entry(1, now + Duration::from_secs(30)), 2, now);
    store.insert(entry(2, now + Duration::from_secs(30)), 2, now);
    store.touch(0);
    store.insert(entry(3, now + Duration::from_secs(30)), 2, now);
    assert!(store.find(42, |entry| entry.key == 1).is_some());
    assert!(store.find(42, |entry| entry.key == 2).is_none());
    let index = store.find(42, |entry| entry.key == 1).unwrap();
    store.modify(index, |entry| entry.expiry = now);
    store.insert(entry(4, now + Duration::from_secs(30)), 2, now);
    assert!(store.find(42, |entry| entry.key == 1).is_none());
    consistent(&store);
}

#[test]
fn expiry_cleanup_is_incremental_and_expired_owner_data_is_never_visible() {
    let now = Instant::now();
    let expiry = now + Duration::from_secs(1);
    let mut store = CacheStore::with_capacity(100);
    for key in 0..100 {
        store.insert(entry(key, expiry), 100, now);
    }
    store.remove_expired(expiry);
    assert_eq!(store.len(), 84);
    for owner in 0u64..3 {
        assert!(store.owner_indices(&owner.to_be_bytes(), expiry).is_empty());
    }
    consistent(&store);
    for _ in 0..6 {
        store.remove_expired(expiry);
    }
    assert_eq!(store.len(), 0);
    consistent(&store);
}

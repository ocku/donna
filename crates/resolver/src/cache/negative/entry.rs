use super::*;

impl CacheEntry for Entry {
    fn engine_key(&self) -> Option<crate::CacheEntryKey> {
        Some(crate::CacheEntryKey {
            family: crate::CacheEntryFamily {
                category: crate::CacheCategory::Negative,
                owner: self.key.owner().to_vec(),
                class: match &self.key {
                    NegativeKey::Name { class, .. } | NegativeKey::Type { class, .. } => {
                        class.value()
                    }
                },
            },
            discriminator: match &self.key {
                NegativeKey::Name { .. } => vec![0],
                NegativeKey::Type { qtype, .. } => {
                    let mut x = vec![1];
                    x.extend_from_slice(&qtype.to_be_bytes());
                    x
                }
            },
        })
    }

    fn hash(&self) -> u64 {
        self.hash
    }
    fn owner(&self) -> &[u8] {
        self.key.owner()
    }
    fn expires_at(&self) -> Instant {
        self.expires_at
    }
    fn hits(&self) -> u32 {
        self.hits
    }
    fn set_hits(&mut self, hits: u32) {
        self.hits = hits;
    }
}

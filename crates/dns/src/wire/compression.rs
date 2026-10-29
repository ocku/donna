use std::collections::HashMap;

/// Small messages need only a few suffixes. Keep those keys inline, promoting
/// to a randomized map before linear lookup or retained key bytes can grow.
#[derive(Debug)]
pub(super) struct CompressionOffsets {
    bytes: [u8; 512],
    entries: [(u16, u16, u16); 16],
    byte_len: usize,
    entry_len: usize,
    large: Option<HashMap<Box<[u8]>, u16>>,
}

impl Default for CompressionOffsets {
    fn default() -> Self {
        Self {
            bytes: [0; 512],
            entries: [(0, 0, 0); 16],
            byte_len: 0,
            entry_len: 0,
            large: None,
        }
    }
}

impl CompressionOffsets {
    pub(super) fn get(&self, suffix: &[u8]) -> Option<u16> {
        if let Some(large) = &self.large {
            return large.get(suffix).copied();
        }
        self.entries[..self.entry_len]
            .iter()
            .find_map(|&(start, len, offset)| {
                (self.bytes[usize::from(start)..usize::from(start + len)] == *suffix)
                    .then_some(offset)
            })
    }

    pub(super) fn insert(&mut self, suffix: &[u8], offset: u16) {
        self.get_or_insert(suffix, Some(offset));
    }

    /// Returns the first target, registering a missing suffix when the caller's
    /// position can still be addressed by a compression pointer. Combining the
    /// operations avoids searching every newly written suffix twice.
    #[inline]
    pub(super) fn get_or_insert(&mut self, suffix: &[u8], offset: Option<u16>) -> Option<u16> {
        if let Some(previous) = self.get(suffix) {
            return Some(previous);
        }
        let offset = offset?;
        self.insert_missing(suffix, offset);
        None
    }

    fn insert_missing(&mut self, suffix: &[u8], offset: u16) {
        if let Some(large) = &mut self.large {
            large.insert(suffix.into(), offset);
            return;
        }
        if self.entry_len < self.entries.len() && self.byte_len + suffix.len() <= self.bytes.len() {
            let end = self.byte_len + suffix.len();
            self.bytes[self.byte_len..end].copy_from_slice(suffix);
            self.entries[self.entry_len] = (self.byte_len as u16, suffix.len() as u16, offset);
            self.entry_len += 1;
            self.byte_len = end;
            return;
        }
        let mut large = HashMap::with_capacity(self.entry_len + 1);
        for &(start, len, offset) in &self.entries[..self.entry_len] {
            let suffix = &self.bytes[usize::from(start)..usize::from(start + len)];
            large.insert(suffix.into(), offset);
        }
        large.insert(suffix.into(), offset);
        self.large = Some(large);
    }

    pub(super) fn retain_before(&mut self, limit: usize) {
        if let Some(large) = &mut self.large {
            large.retain(|_, offset| usize::from(*offset) < limit);
        } else {
            let mut retained = 0;
            for index in 0..self.entry_len {
                let entry = self.entries[index];
                if usize::from(entry.2) < limit {
                    self.entries[retained] = entry;
                    retained += 1;
                }
            }
            self.entry_len = retained;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_promotion_and_rollback_preserve_first_targets() {
        let mut offsets = CompressionOffsets::default();
        let mut expected = HashMap::new();
        let mut keys = Vec::new();
        for index in 0..200_u16 {
            let mut key = vec![index as u8; usize::from(index % 127) + 1];
            key.extend_from_slice(&index.to_be_bytes());
            keys.push(key);
            for (suffix, offset) in [(&keys[usize::from(index)], index), (&keys[0], 999)] {
                offsets.insert(suffix, offset);
                expected.entry(suffix.clone()).or_insert(offset);
            }
            if index % 9 == 0 {
                let limit = usize::from(index.saturating_sub(3));
                offsets.retain_before(limit);
                expected.retain(|_, offset| usize::from(*offset) < limit);
            }
            for key in &keys {
                assert_eq!(offsets.get(key), expected.get(key).copied());
            }
        }
        assert!(offsets.large.is_some());
    }
}

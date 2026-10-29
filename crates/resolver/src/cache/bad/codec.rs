use super::*;
use crate::cache::codec::{Reader, Writer, question_from_codes};
use std::io;

impl BadCache {
    pub(crate) fn engine_accesses(&self) -> Vec<crate::CacheEntryKey> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accesses()
            .to_vec()
    }
    pub(crate) fn for_engine(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(crate::cache::entries::CacheEntries::view()),
        }
    }

    pub(crate) fn encode_entries(&self, out: &mut Writer<'_>) -> io::Result<()> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        out.count(entries.values.len())?;
        for entry in &entries.values {
            out.begin_entry(entry, &[])?;
            out.wire(&question_from_codes(
                &entry.key.qname,
                entry.key.qtype,
                entry.key.qclass,
            )?)?;
            out.byte(entry.failures)?;
            out.instant(entry.expires_at)?;
            out.end_entry()?;
        }
        Ok(())
    }
    pub(crate) fn decode_entries(&self, input: &mut Reader<'_>) -> io::Result<()> {
        let count = input.items(self.capacity, 26)?;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let question = input.question()?;
            let key = Key::new(&question);
            let failures = input.byte()?;
            let expires_at = input.instant()?;
            values.push(Entry {
                hash: entries.hash_key(&key),
                key,
                failures,
                expires_at,
            });
        }
        entries.restore_values(values);
        Ok(())
    }
}

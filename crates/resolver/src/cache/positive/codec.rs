use super::*;
use crate::{
    cache::codec::{Reader, Writer, invalid, question_from_codes},
    name::packed_key,
};
use std::io;

impl PositiveCache {
    pub(crate) fn engine_removals(&self) -> Vec<crate::CacheEntryKey> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .removals()
            .to_vec()
    }
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
            key_hasher: RandomState::new(),
            entries: Mutex::new(Entries::view()),
            maybe_authenticated_dname: AtomicBool::new(false),
        }
    }

    pub(crate) fn encode_entries(&self, out: &mut Writer<'_>) -> io::Result<()> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        out.count(entries.values.len())?;
        for entry in &entries.values {
            out.begin_entry(entry, &entry.response.answers)?;
            let question =
                question_from_codes(&entry.key.qname, entry.key.qtype, entry.key.qclass)?;
            out.wire(&question)?;
            out.instant(entry.expires_at)?;
            out.u32(entry.hits)?;
            out.flag(entry.authoritative)?;
            out.flag(entry.authenticated)?;
            out.records(&entry.response.answers)?;
            out.records(&entry.response.authorities)?;
            out.end_entry()?;
        }
        Ok(())
    }
    pub(crate) fn decode_entries(&self, input: &mut Reader<'_>) -> io::Result<()> {
        let count = input.items(self.capacity, 54)?;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let question = input.question()?;
            let expires_at = input.instant()?;
            let hits = input.u32()?;
            let authoritative = input.flag()?;
            let authenticated = input.flag()?;
            if authenticated && question.qtype.value() == u16::from(RecordType::DNAME) {
                self.maybe_authenticated_dname
                    .store(true, Ordering::Release);
            }
            let answers = input.records()?;
            let authorities = input.records()?;
            if answers.is_empty() {
                return Err(invalid());
            }
            let owner_data = owner_data(&question, &answers);
            values.push(Entry {
                hash: self.hash_question(&question),
                expires_at,
                hits,
                authoritative,
                authenticated,
                owner_data,
                key: CacheKey {
                    qname: packed_key(&question.qname),
                    qtype: question.qtype.value(),
                    qclass: question.qclass.value(),
                },
                response: Arc::new(PackedResponse::from_records(answers, authorities)),
                prepared: [const { OnceLock::new() }; 2],
            });
        }
        entries.restore_values(values);
        Ok(())
    }
}

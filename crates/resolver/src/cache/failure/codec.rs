use super::*;
use crate::cache::codec::{Reader, Writer, invalid, question_from_codes};
use std::io;

impl FailureCache {
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
                &entry.key.name,
                entry.key.qtype,
                entry.key.qclass,
            )?)?;
            out.flag(entry.key.checking_disabled)?;
            out.byte(match entry.kind {
                FailureKind::Unreachable => 0,
                FailureKind::Server => 1,
                FailureKind::AliasLoop => 3,
                FailureKind::Bogus => 4,
                FailureKind::Indeterminate => 5,
                FailureKind::Transport => 6,
            })?;
            out.instant(entry.suppress_until)?;
            out.instant(entry.history_until)?;
            out.raw(&(entry.interval.as_nanos() as u64).to_be_bytes())?;
            out.end_entry()?;
        }
        Ok(())
    }

    pub(crate) fn decode_entries(&self, input: &mut Reader<'_>) -> io::Result<()> {
        let count = input.items(self.capacity, 51)?;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let question = input.question()?;
            let key = Key::new(&question, input.flag()?);
            let kind = match input.byte()? {
                0 => FailureKind::Unreachable,
                1 => FailureKind::Server,
                3 => FailureKind::AliasLoop,
                4 => FailureKind::Bogus,
                5 => FailureKind::Indeterminate,
                6 => FailureKind::Transport,
                _ => return Err(invalid()),
            };
            let suppress_until = input.instant()?;
            let history_until = input.instant()?;
            let nanos = u64::from_be_bytes(input.raw(8)?.try_into().map_err(|_| invalid())?);
            let interval = Duration::from_nanos(nanos);
            if !(Duration::from_secs(1)..=Duration::from_secs(300)).contains(&interval)
                || history_until < suppress_until
                || history_until.duration_since(suppress_until) > Duration::from_secs(300)
            {
                return Err(invalid());
            }
            values.push(Entry {
                hash: entries.hash_key(&key),
                key,
                kind,
                suppress_until,
                history_until,
                interval,
            });
        }
        entries.restore_values(values);
        Ok(())
    }
}

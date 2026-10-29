//! RFC 9520 terminal failures, scoped to a complete client question and CD mode.
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use dns::Question;

use crate::{
    ResolveError, cache::entries::CacheEntries, cache::store::CacheEntry, name::packed_key,
};

mod codec;
#[cfg(test)]
mod tests;

pub(crate) struct FailureCache {
    capacity: usize,
    entries: Mutex<CacheEntries<Entry>>,
}

#[derive(Eq, Hash, PartialEq)]
struct Key {
    name: Box<[u8]>,
    qtype: u16,
    qclass: u16,
    checking_disabled: bool,
}

impl Key {
    fn new(question: &Question, checking_disabled: bool) -> Self {
        Self {
            name: packed_key(&question.qname),
            qtype: question.qtype.value(),
            qclass: question.qclass.value(),
            checking_disabled,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FailureKind {
    Unreachable,
    Server,
    AliasLoop,
    Bogus,
    Indeterminate,
    Transport,
}

impl FailureKind {
    pub(crate) fn from_error(error: &ResolveError) -> Option<Self> {
        Some(match error {
            ResolveError::NoReachableServer => Self::Unreachable,
            ResolveError::TemporaryServerFailure => Self::Server,
            ResolveError::CnameLoop => Self::AliasLoop,
            ResolveError::DnssecBogus(_) => Self::Bogus,
            ResolveError::DnssecIndeterminate(_) => Self::Indeterminate,
            ResolveError::Transport(transport::TransportError::Timeout) => Self::Transport,
            ResolveError::Transport(transport::TransportError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        // tokio-rustls reports rejected remote handshakes and
                        // certificates as InvalidData; local request encoding
                        // has its own non-cacheable TransportError variants.
                        | std::io::ErrorKind::InvalidData
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::NetworkDown
                        | std::io::ErrorKind::NetworkUnreachable
                        | std::io::ErrorKind::HostUnreachable
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                Self::Transport
            }
            ResolveError::UnsupportedQuestion
            | ResolveError::CachedNameServerFailure
            | ResolveError::CachedDelegationFailure
            | ResolveError::DelegationRefreshInProgress
            | ResolveError::WorkLimitExceeded
            | ResolveError::CacheBackend(_)
            | ResolveError::Transport(_) => return None,
        })
    }

    pub(crate) fn error(self) -> ResolveError {
        match self {
            Self::Unreachable => ResolveError::NoReachableServer,
            Self::Server => ResolveError::TemporaryServerFailure,
            Self::AliasLoop => ResolveError::CnameLoop,
            Self::Bogus => ResolveError::DnssecBogus(dns::DnssecValidationError::NoValidSignature),
            Self::Indeterminate => {
                ResolveError::DnssecIndeterminate(dns::DnssecValidationError::NoValidSignature)
            }
            Self::Transport => ResolveError::Transport(transport::TransportError::Io(
                std::io::Error::other("cached DNS transport failure"),
            )),
        }
    }
}

struct Entry {
    key: Key,
    hash: u64,
    kind: FailureKind,
    suppress_until: Instant,
    history_until: Instant,
    interval: Duration,
}

impl CacheEntry for Entry {
    fn engine_key(&self) -> Option<crate::CacheEntryKey> {
        Some(crate::CacheEntryKey {
            family: crate::CacheEntryFamily {
                category: crate::CacheCategory::Failure,
                owner: self.key.name.to_vec(),
                class: self.key.qclass,
            },
            discriminator: {
                let mut x = self.key.qtype.to_be_bytes().to_vec();
                x.push(u8::from(self.key.checking_disabled));
                x
            },
        })
    }

    fn hash(&self) -> u64 {
        self.hash
    }
    fn owner(&self) -> &[u8] {
        &self.key.name
    }
    fn expires_at(&self) -> Instant {
        self.history_until
    }
    fn hits(&self) -> u32 {
        0
    }
    fn set_hits(&mut self, _: u32) {}
}

impl FailureCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(CacheEntries::with_capacity(capacity)),
        }
    }

    pub(crate) fn get(&self, question: &Question, checking_disabled: bool) -> Option<FailureKind> {
        self.lookup(question, checking_disabled).0
    }

    pub(crate) fn lookup(
        &self,
        question: &Question,
        checking_disabled: bool,
    ) -> (Option<FailureKind>, bool) {
        if self.capacity == 0 {
            return (None, false);
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = Key::new(question, checking_disabled);
        let hash = entries.hash_key(&key);
        let Some(index) = entries.find(hash, |entry| entry.key == key) else {
            return (None, false);
        };
        if entries.values[index].history_until <= Instant::now() {
            entries.remove(index);
            return (None, false);
        }
        entries.note_access(index);
        if entries.values[index].suppress_until <= Instant::now() {
            return (None, true);
        }
        (Some(entries.values[index].kind), false)
    }

    pub(crate) fn insert(
        &self,
        question: &Question,
        checking_disabled: bool,
        kind: FailureKind,
        ttl: Duration,
    ) {
        if self.capacity == 0 {
            return;
        }
        let now = Instant::now();
        let ttl = ttl.clamp(Duration::from_secs(1), Duration::from_secs(300));
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.remove_expired(now);
        let key = Key::new(question, checking_disabled);
        let hash = entries.hash_key(&key);
        if let Some(index) = entries.find(hash, |entry| entry.key == key) {
            if entries.values[index].history_until <= now {
                entries.remove(index);
            } else {
                // Concurrent failures cannot keep extending an existing suppression
                // window. After expiry, the next actual resolution starts a new one.
                if entries.values[index].suppress_until > now {
                    return;
                }
                let interval = entries.values[index]
                    .interval
                    .saturating_mul(2)
                    .min(Duration::from_secs(300));
                entries.modify(index, |entry| {
                    entry.kind = kind;
                    entry.interval = interval;
                    entry.suppress_until = now + interval;
                    entry.history_until = entry.suppress_until + Duration::from_secs(300);
                });
                return;
            }
        }
        if entries.len() == self.capacity {
            entries.remove_earliest();
        }
        entries.insert(
            Entry {
                key,
                hash,
                kind,
                suppress_until: now + ttl,
                history_until: now + ttl + Duration::from_secs(300),
                interval: ttl,
            },
            self.capacity,
            now,
        );
    }

    /// A useful response resets expired failure history; never erase a newer
    /// concurrent failure that is still suppressing queries.
    pub(crate) fn clear_expired(&self, question: &Question, checking_disabled: bool) {
        if self.capacity == 0 {
            return;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = Key::new(question, checking_disabled);
        let hash = entries.hash_key(&key);
        if let Some(index) = entries.find(hash, |entry| entry.key == key)
            && entries.values[index].suppress_until <= Instant::now()
        {
            entries.remove(index);
        }
    }
}

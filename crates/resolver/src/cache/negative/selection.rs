//! Project selected negative entries while preserving per-record lifetimes.

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use dns::{Headers, Message, Question, RCode, ResourceRecord};

use super::{ComposedNegative, NegativeCache, NegativeRecords};

#[derive(Clone)]
pub(crate) struct DenialKeys {
    pub(crate) original: std::sync::Weak<dns::AuthenticatedDnskeySet>,
    pub(crate) memoized: Arc<dns::AuthenticatedDnskeySet>,
}

/// Immutable authority storage retained only for the current synchronous query.
/// Selection fixes which records were live; encoding may lower TTLs to zero.
pub(crate) struct SelectedNegative {
    pub(super) authorities: Arc<NegativeRecords>,
    pub(super) expires_at: Instant,
    pub(super) selected_at: Instant,
    pub(crate) authenticated: bool,
    pub(crate) rcode: RCode,
    pub(crate) prepare_composition: bool,
}

impl SelectedNegative {
    /// Reuse mathematical success only under the same current authenticated
    /// key object. Rehydrated/replaced contexts rebuild and verify normally.
    pub(crate) fn memoized_denial_keys(
        &self,
        keys: &Arc<dns::AuthenticatedDnskeySet>,
    ) -> Arc<dns::AuthenticatedDnskeySet> {
        let mut slot = self
            .authorities
            .denial_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = slot.as_ref()
            && cached
                .original
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, keys))
        {
            return Arc::clone(&cached.memoized);
        }
        let memoized = Arc::new(keys.with_denial_validation_cache());
        *slot = Some(super::DenialKeys {
            original: Arc::downgrade(keys),
            memoized: Arc::clone(&memoized),
        });
        memoized
    }
    pub(crate) fn is_live(&self) -> bool {
        self.expires_at > Instant::now()
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.expires_at
    }

    pub(crate) fn authorities(&self) -> impl Iterator<Item = (&ResourceRecord, u32)> {
        let now = Instant::now().max(self.selected_at);
        self.authorities.iter().filter_map(move |cached| {
            let expires_at = cached.expires_at.min(self.expires_at);
            (expires_at > self.selected_at
                && super::keep_authority(&cached.record, self.authenticated))
            .then(|| {
                (
                    &cached.record,
                    expires_at
                        .saturating_duration_since(now)
                        .as_secs()
                        .min(u64::from(u32::MAX)) as u32,
                )
            })
        })
    }

    pub(crate) fn all_authorities_live_at_selection(&self) -> bool {
        self.authorities
            .iter()
            .all(|rr| rr.expires_at.min(self.expires_at) > self.selected_at)
    }

    pub(crate) fn compositions(&self) -> &Mutex<[Option<Box<ComposedNegative>>; 2]> {
        self.authorities
            .composed
            .get_or_init(|| Mutex::new([None, None]))
    }

    pub(crate) fn materialize(&self, question: &Question) -> Message {
        Message {
            headers: Headers {
                qr: true,
                ad: self.authenticated,
                rcode: self.rcode,
                ..Headers::default()
            },
            questions: vec![question.clone()],
            answers: Vec::new(),
            authorities: self
                .authorities()
                .map(|(record, ttl)| {
                    let mut record = record.clone();
                    record.ttl = ttl;
                    record
                })
                .collect(),
            additionals: Vec::new(),
        }
    }
}

impl NegativeCache {
    pub(crate) fn select(&self, question: &Question) -> Option<SelectedNegative> {
        self.with_entry(question, |entry, now| SelectedNegative {
            authorities: Arc::clone(&entry.authorities),
            expires_at: entry.expires_at,
            selected_at: now,
            authenticated: entry.authenticated,
            rcode: entry.rcode,
            // Measured setup is tens of microseconds: avoid paying it for
            // infrequently reused entries. Read the existing popularity rank;
            // selection still performs exactly its ordinary single touch.
            prepare_composition: entry.hits >= crate::cache::store::NEGATIVE_COMPOSITION_MIN_HITS,
        })
    }
}

impl NegativeCache {
    /// Select only a strict ancestor's name-error scope, touching it once.
    pub(crate) fn select_name_error_ancestor(
        &self,
        question: &Question,
    ) -> Option<(Question, SelectedNegative)> {
        let dns::QClassType::Class(class) = question.qclass else {
            return None;
        };
        let packed = crate::name::PackedName::new(&question.qname);
        let wire = packed.as_ref();
        let mut offset = 0;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for first in 1..=question.qname.as_ref().len() {
            offset += usize::from(wire[offset]) + 1;
            let key = super::NegativeKeyRef::Name {
                qname: &wire[offset..],
                class,
            };
            let Some(index) = entries.find(entries.hash_key(&key), |e| e.key.as_ref() == key)
            else {
                continue;
            };
            let now = Instant::now();
            let entry = &entries.values[index];
            if entry.expires_at <= now || !entry.authenticated {
                continue;
            }
            let source = Question {
                qname: dns::DomainName::from_labels(question.qname.as_ref()[first..].to_vec())
                    .ok()?,
                ..question.clone()
            };
            entries.touch(index);
            let entry = &entries.values[index];
            return Some((
                source,
                SelectedNegative {
                    authorities: Arc::clone(&entry.authorities),
                    expires_at: entry.expires_at,
                    selected_at: now,
                    authenticated: entry.authenticated,
                    rcode: entry.rcode,
                    prepare_composition: false,
                },
            ));
        }
        None
    }

    /// Publication recheck changes neither popularity nor eviction state.
    pub(crate) fn retains_name_error(
        &self,
        source: &Question,
        selected: &SelectedNegative,
    ) -> bool {
        let dns::QClassType::Class(class) = source.qclass else {
            return false;
        };
        let packed = crate::name::PackedName::new(&source.qname);
        let key = super::NegativeKeyRef::Name {
            qname: packed.as_ref(),
            class,
        };
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .find(entries.hash_key(&key), |e| e.key.as_ref() == key)
            .is_some_and(|index| {
                let entry = &entries.values[index];
                entry.authenticated
                    && entry.expires_at > Instant::now()
                    && entry.expires_at == selected.expires_at
                    && Arc::ptr_eq(&entry.authorities, &selected.authorities)
            })
    }
}

impl NegativeCache {
    pub(crate) fn seed_name_error_keys(&self, question: &Question, keys: super::DenialKeys) {
        let dns::QClassType::Class(class) = question.qclass else {
            return;
        };
        let packed = crate::name::PackedName::new(&question.qname);
        let key = super::NegativeKeyRef::Name {
            qname: packed.as_ref(),
            class,
        };
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = entries.find(entries.hash_key(&key), |e| e.key.as_ref() == key) {
            let entry = &entries.values[index];
            if entry.authenticated && entry.expires_at > Instant::now() {
                *entry
                    .authorities
                    .denial_keys
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(keys);
            }
        }
    }
}

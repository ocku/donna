use super::{Entry, PackedResponse};
use dns::ResourceRecord;
use std::{sync::Arc, time::Instant};

/// An admitted, live-at-selection RRset retained for this synchronous traversal.
/// This is never put in a composite cache or reused by a later transaction.
pub(crate) struct SelectedPositive {
    response: Arc<PackedResponse>,
    expires_at: Instant,
    selected_ttl: u32,
    pub(crate) authenticated: bool,
    pub(crate) frequent: bool,
}

impl SelectedPositive {
    pub(crate) fn is_live(&self) -> bool {
        self.expires_at > Instant::now()
    }

    pub(super) fn new(entry: &Entry, now: Instant) -> Self {
        Self {
            response: Arc::clone(&entry.response),
            expires_at: entry.expires_at,
            selected_ttl: entry
                .expires_at
                .saturating_duration_since(now)
                .as_secs()
                .min(u64::from(u32::MAX)) as u32,
            authenticated: entry.authenticated,
            frequent: entry.hits >= crate::cache::store::NEGATIVE_COMPOSITION_MIN_HITS,
        }
    }

    pub(crate) fn answers(&self) -> &[ResourceRecord] {
        &self.response.answers
    }
    pub(crate) fn authorities(&self) -> &[ResourceRecord] {
        &self.response.authorities
    }

    pub(crate) fn into_message(self, question: &dns::Question) -> dns::Message {
        self.response.to_message(
            question,
            &dns::Headers::default(),
            std::time::Duration::from_secs(u64::from(self.ttl())),
            self.authenticated,
        )
    }

    pub(crate) fn ttl(&self) -> u32 {
        // A live selection may finish this transaction at TTL zero, just as a
        // materialized reply may expire before it is sent. It cannot extend
        // either the lookup-time TTL or the admitted absolute entry deadline.
        self.selected_ttl.min(
            self.expires_at
                .saturating_duration_since(Instant::now())
                .as_secs()
                .min(u64::from(u32::MAX)) as u32,
        )
    }
}

/// At most one composition per DO policy is attached to an admitted response.
/// Weak identities retain no record storage or live selections.
pub(crate) struct ComposedPositive {
    pub(crate) identities: Vec<SelectionIdentity>,
    pub(crate) reply: dns::wire::PreparedPositiveReply,
}

#[derive(Clone)]
pub(crate) struct SelectionIdentity {
    response: std::sync::Weak<PackedResponse>,
    expires_at: Instant,
    authenticated: bool,
}

impl SelectionIdentity {
    pub(crate) fn is_live(&self, now: Instant) -> bool {
        self.response.strong_count() != 0 && self.expires_at > now
    }
}

impl SelectedPositive {
    pub(crate) fn identity(&self) -> SelectionIdentity {
        SelectionIdentity {
            response: Arc::downgrade(&self.response),
            expires_at: self.expires_at,
            authenticated: self.authenticated,
        }
    }

    pub(crate) fn matches_identity(&self, identity: &SelectionIdentity) -> bool {
        identity.response.as_ptr() == Arc::as_ptr(&self.response)
            && identity.expires_at == self.expires_at
            && identity.authenticated == self.authenticated
    }

    pub(crate) fn compositions(&self) -> &std::sync::Mutex<[Option<Box<ComposedPositive>>; 2]> {
        self.response
            .composed
            .get_or_init(|| std::sync::Mutex::new([None, None]))
    }
}

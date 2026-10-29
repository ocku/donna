//! Bounded preparation attached to existing immutable zone nodes.
use dns::{
    Message, ResourceRecord,
    wire::{EncodedReply, PreparedAuthoritativeNodataReply},
};
use std::sync::{
    OnceLock,
    atomic::{AtomicU32, Ordering},
};

const MIN_HITS: u32 = 32;
const MAX_NODES: u32 = 64;

#[derive(Debug, Default)]
pub(crate) struct NodataCache {
    hits: AtomicU32,
    variants: OnceLock<Option<Box<Variants>>>,
}

#[derive(Debug, Default)]
struct Variants {
    replies: [OnceLock<Option<PreparedAuthoritativeNodataReply>>; 2],
}

impl NodataCache {
    pub(crate) fn render(
        &self,
        query: &Message,
        dnssec_ok: bool,
        maximum: usize,
    ) -> Option<EncodedReply> {
        self.variants.get()?.as_ref()?.replies[usize::from(dnssec_ok)]
            .get()?
            .as_ref()?
            .render(query, maximum)
    }

    pub(super) fn prepare(
        &self,
        budget: &AtomicU32,
        query: &Message,
        dnssec_ok: bool,
        authorities: &[&ResourceRecord],
    ) {
        let mut hits = self.hits.load(Ordering::Relaxed);
        while hits < MIN_HITS {
            match self.hits.compare_exchange_weak(
                hits,
                hits + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    if hits + 1 < MIN_HITS {
                        return;
                    }
                    break;
                }
                Err(current) => hits = current,
            }
        }
        let Some(variants) = self.variants.get_or_init(|| {
            let mut used = budget.load(Ordering::Relaxed);
            while used < MAX_NODES {
                match budget.compare_exchange_weak(
                    used,
                    used + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Some(Box::default()),
                    Err(current) => used = current,
                }
            }
            None
        }) else {
            return;
        };
        variants.replies[usize::from(dnssec_ok)].get_or_init(|| {
            PreparedAuthoritativeNodataReply::from_records(query, authorities)
                .ok()
                .flatten()
        });
    }
}

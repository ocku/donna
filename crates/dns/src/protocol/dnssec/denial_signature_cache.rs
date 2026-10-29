//! Bounded mathematical results for one retained denial proof, never trust/time.
use crate::protocol::SuccessfulSignatureCache;
use crate::{ClassType, DomainName, RecordType, ResourceRecord};
use std::sync::{Arc, Mutex};

const MAX_RRSETS: usize = 8;
type Key = (DomainName, RecordType, ClassType);
#[derive(Debug, Default)]
pub(crate) struct DenialSignatureCache(Mutex<Vec<(Key, Arc<SuccessfulSignatureCache>)>>);
impl DenialSignatureCache {
    pub(crate) fn for_rrset(
        &self,
        records: &[ResourceRecord],
    ) -> Option<Arc<SuccessfulSignatureCache>> {
        let first = records.first()?;
        if !matches!(first.rtype, RecordType::NSEC | RecordType::NSEC3) {
            return None;
        }
        let mut entries = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, cache)) = entries.iter().find(|((owner, rtype, class), _)| {
            owner.eq_dns(&first.name) && *rtype == first.rtype && *class == first.class
        }) {
            return Some(Arc::clone(cache));
        }
        if entries.len() == MAX_RRSETS {
            return None;
        }
        let cache = Arc::new(SuccessfulSignatureCache::default());
        entries.push((
            (first.name.clone(), first.rtype, first.class),
            Arc::clone(&cache),
        ));
        Some(cache)
    }
}

impl super::AuthenticatedDnskeySet {
    /// Clones these authenticated keys with bounded denial-signature math
    /// memoization for one retained proof. This creates no authentication,
    /// freshness, or TTL decision and is excluded from cache export material.
    pub fn with_denial_validation_cache(&self) -> Self {
        let mut keys = self.clone();
        keys.denial_signatures = Some(Default::default());
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    fn proof(index: usize) -> ResourceRecord {
        let name = DomainName::from_dotted(&format!("n{index}.example.")).unwrap();
        ResourceRecord {
            name: name.clone(),
            rtype: RecordType::NSEC,
            class: ClassType::IN,
            ttl: 60,
            rdata: crate::RData::NSEC(crate::Nsec {
                next_domain_name: name,
                type_bitmap: crate::TypeBitmap::new([47]).unwrap(),
            }),
        }
    }
    #[test]
    fn proof_memo_bounds_rrsets_and_routing_never_substitutes_for_exact_math_identity() {
        let memo = DenialSignatureCache::default();
        let first = proof(0);
        let slot = memo.for_rrset(std::slice::from_ref(&first)).unwrap();
        let calls = Cell::new(0);
        let verify = || {
            calls.set(calls.get() + 1);
            Ok(())
        };
        slot.verify(13, b"key", b"signed data", b"signature", verify)
            .unwrap();
        slot.verify(13, b"key", b"signed data", b"signature", || {
            panic!("repeat math")
        })
        .unwrap();
        let mut changed = first.clone();
        changed.rdata = proof(1).rdata;
        let same_route = memo.for_rrset(&[changed]).unwrap();
        assert!(Arc::ptr_eq(&slot, &same_route));
        same_route
            .verify(13, b"key", b"changed signed data", b"signature", verify)
            .unwrap();
        same_route
            .verify(
                13,
                b"other key",
                b"changed signed data",
                b"signature",
                verify,
            )
            .unwrap();
        assert_eq!(calls.get(), 3);
        for index in 1..MAX_RRSETS {
            assert!(memo.for_rrset(&[proof(index)]).is_some());
        }
        assert!(memo.for_rrset(&[proof(MAX_RRSETS)]).is_none());
        assert!(Arc::ptr_eq(&slot, &memo.for_rrset(&[first]).unwrap()));
    }
}

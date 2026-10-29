//! Snapshot-owned known-node hashes, never a cache of queried names.
use std::num::NonZeroUsize;

use super::{BorrowedEncloser, Entry, Nsec3Index};
use crate::{
    name::{dns_name_key_into, suffixes},
    zone::lookup::ZoneLookupIndex,
};
use dns::{DomainName, Nsec3ClosestEncloserProof};

#[derive(Debug)]
pub(super) struct PrelinkedNode {
    hash: [u8; 20],
    matching_entry: Option<NonZeroUsize>,
    wildcard_cover: Option<NonZeroUsize>,
}

impl Nsec3Index {
    pub(in crate::zone) fn reserve_nodes(&mut self, capacity: usize) {
        self.nodes.reserve_exact(capacity);
    }

    pub(in crate::zone) fn register_node(&mut self, name: &DomainName) -> Option<NonZeroUsize> {
        let hash = self.hash(name)?;
        let matching_entry = self
            .entries
            .binary_search_by_key(&hash, |entry| entry.hash)
            .ok()
            .and_then(|index| NonZeroUsize::new(index + 1));
        let position = NonZeroUsize::new(self.nodes.len().checked_add(1)?)?;
        let wildcard_cover = crate::zone::dnssec::wildcard_name(name)
            .and_then(|wildcard| self.covering(&wildcard))
            .and_then(|record| NonZeroUsize::new(record + 1));
        self.nodes.push(PrelinkedNode {
            hash,
            matching_entry,
            wildcard_cover,
        });
        Some(position)
    }

    pub(in crate::zone) fn name_error_proof_indices(
        &self,
        apex: &DomainName,
        qname: &DomainName,
        lookup: &ZoneLookupIndex,
    ) -> smallvec::SmallVec<[usize; 3]> {
        let Some(proof) = self.closest_encloser_labels_linked(apex, qname, lookup) else {
            return smallvec::SmallVec::new();
        };
        let mut selected = smallvec::smallvec![proof.matching_record, proof.covering_record];
        let wildcard = proof.wildcard_cover.unwrap_or_else(|| {
            let closest = DomainName::from_labels(proof.labels.to_vec()).ok()?;
            let wildcard = crate::zone::dnssec::wildcard_name(&closest)?;
            self.covering(&wildcard)
        });
        if let Some(record) = wildcard {
            selected.push(record);
        }
        selected
    }

    #[cfg(test)]
    pub(in crate::zone) fn metadata_usage(&self) -> (usize, usize) {
        (
            self.nodes.len(),
            self.nodes.capacity() * std::mem::size_of::<PrelinkedNode>(),
        )
    }

    fn node<'a>(&'a self, key: &[u8], lookup: &ZoneLookupIndex) -> Option<&'a PrelinkedNode> {
        self.nodes.get(lookup.nsec3_link_at_key(key)?)
    }

    fn matching_entry(&self, node: &PrelinkedNode) -> Option<&Entry> {
        self.entries.get(node.matching_entry?.get() - 1)
    }

    pub(in crate::zone) fn matching_linked(
        &self,
        name: &DomainName,
        lookup: &ZoneLookupIndex,
    ) -> Option<usize> {
        let mut storage = [0; 255];
        if let Some(node) = self.node(dns_name_key_into(name, &mut storage), lookup) {
            return self.matching_entry(node).map(|entry| entry.record);
        }
        self.matching(name)
    }

    pub(in crate::zone) fn closest_encloser_linked(
        &self,
        apex: &DomainName,
        qname: &DomainName,
        lookup: &ZoneLookupIndex,
    ) -> Option<Nsec3ClosestEncloserProof> {
        if self.nodes.is_empty() {
            return self.closest_encloser(apex, qname);
        }
        let proof = self.closest_encloser_labels_linked(apex, qname, lookup)?;
        Some(Nsec3ClosestEncloserProof {
            closest_encloser: DomainName::from_labels(proof.labels.to_vec()).ok()?,
            matching_record: proof.matching_record,
            covering_record: proof.covering_record,
        })
    }

    pub(in crate::zone) fn closest_encloser_labels_linked<'a>(
        &self,
        apex: &DomainName,
        qname: &'a DomainName,
        lookup: &ZoneLookupIndex,
    ) -> Option<BorrowedEncloser<'a>> {
        if self.nodes.is_empty() {
            return self.closest_encloser_labels(apex, qname);
        }
        if !qname.is_descendant_of(apex) || qname.as_ref().len() <= apex.as_ref().len() {
            return None;
        }
        let mut storage = [0; 255];
        let mut keys = suffixes(dns_name_key_into(qname, &mut storage));
        let mut hashes = self
            .parameters
            .hash_name_suffixes_fixed(qname, self.parameters.iterations);
        let mut next_unhashed = 0;
        let mut hash = |dropped| {
            let key = keys.next()?;
            if let Some(node) = self.node(key, lookup) {
                return Some((
                    node.hash,
                    self.matching_entry(node),
                    Some(node.wildcard_cover.map(|record| record.get() - 1)),
                ));
            }
            // Map::nth skips the already linked suffixes without hashing them.
            let digest = hashes.nth(dropped - next_unhashed)?.ok()?;
            next_unhashed = dropped + 1;
            Some((digest, self.exact_hash(&digest), None))
        };
        let (mut next_hash, _, _) = hash(0)?;
        for dropped in 1..=qname.as_ref().len() - apex.as_ref().len() {
            let (closest_hash, matching, wildcard_cover) = hash(dropped)?;
            let covering = self.covering_hash(&next_hash);
            next_hash = closest_hash;
            if let (Some(matching), Some(covering)) = (matching, covering) {
                if !matching.valid_encloser {
                    return None;
                }
                return Some(BorrowedEncloser {
                    labels: &qname.as_ref()[dropped..],
                    matching_record: matching.record,
                    covering_record: covering.record,
                    wildcard_cover,
                });
            }
        }
        None
    }
}

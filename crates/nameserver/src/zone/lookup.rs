use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
};

use dns::{DomainName, FromWire, QueryType, RData, RecordType, ResourceRecord};

use crate::name::{DnsNameKey, dns_name_key, dns_name_key_into, suffixes};

/// Reuses the original delegation flag's alignment slot for snapshot links.
#[derive(Debug, Default)]
struct NodeMetadata(usize);

impl NodeMetadata {
    const DELEGATION: usize = 1;
    const ORIGINAL: usize = 2;
    const DNAME: usize = 4;

    fn mark_original(&mut self) {
        self.0 |= Self::ORIGINAL;
    }
    fn is_original(&self) -> bool {
        self.0 & Self::ORIGINAL != 0
    }

    fn mark_delegation(&mut self) {
        self.0 |= Self::DELEGATION;
    }

    fn is_delegation(&self) -> bool {
        self.0 & Self::DELEGATION != 0
    }

    fn mark_dname(&mut self) {
        self.0 |= Self::DNAME;
    }

    fn is_dname(&self) -> bool {
        self.0 & Self::DNAME != 0
    }

    fn set_nsec3_link(&mut self, position: Option<NonZeroUsize>) {
        // A link that cannot fit the tag word retains ordinary hashing. The
        // delegation flag is independent, including on 32-bit platforms.
        let encoded = position
            .and_then(|position| position.get().checked_mul(8))
            .unwrap_or(0);
        self.0 = (self.0 & (Self::DELEGATION | Self::ORIGINAL | Self::DNAME)) | encoded;
    }

    fn nsec3_link(&self) -> Option<usize> {
        (self.0 >> 3).checked_sub(1)
    }
}

#[derive(Debug, Default)]
struct Node {
    records: Vec<usize>,
    metadata: NodeMetadata,
    nodata: super::nodata::NodataCache,
}

#[derive(Debug)]
pub(super) struct ZoneLookupIndex {
    nodes: HashMap<DnsNameKey, Node>,
}

#[cfg(test)]
thread_local! { static NODE_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
fn probe() {
    NODE_PROBES.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
pub(super) fn counted_probes<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    NODE_PROBES.with(|count| count.set(0));
    let result = operation();
    (result, NODE_PROBES.with(std::cell::Cell::get))
}

/// One immutable node selection. A present empty exact/wildcard node is an
/// empty nonterminal, distinct from a missing logical node.
pub(super) enum NodeSelection<'index, 'key> {
    Delegation {
        key: &'key [u8],
        records: &'index [usize],
    },
    Dname(&'index [usize]),
    Exact(&'index [usize]),
    Wildcard {
        skipped: usize,
        records: &'index [usize],
    },
    Missing,
}

impl ZoneLookupIndex {
    pub(super) fn select<'index, 'key>(
        &'index self,
        key: &'key [u8],
    ) -> NodeSelection<'index, 'key> {
        let mut boundary = None;
        let mut closest = None;
        for (skipped, suffix) in suffixes(key).enumerate() {
            #[cfg(test)]
            probe();
            let Some(node) = self.nodes.get(suffix) else {
                continue;
            };
            if node.metadata.is_delegation() {
                // Traversal runs toward the root: the last cut is the same
                // outermost cut selected by the original independent probes.
                boundary = Some(NodeSelection::Delegation {
                    key: suffix,
                    records: if node.metadata.is_original() {
                        &node.records
                    } else {
                        &[]
                    },
                });
            } else if skipped != 0 && node.metadata.is_dname() {
                boundary = Some(NodeSelection::Dname(&node.records));
            }
            if closest.is_none() && node.metadata.is_original() {
                closest = Some((skipped, suffix, node));
            }
        }
        if let Some(boundary) = boundary {
            return boundary;
        }
        let Some((skipped, suffix, node)) = closest else {
            return NodeSelection::Missing;
        };
        if skipped == 0 {
            return NodeSelection::Exact(&node.records);
        }
        let length = suffix.len() + 2;
        if length > 255 {
            return NodeSelection::Missing;
        }
        let mut wildcard = [0; 255];
        wildcard[..2].copy_from_slice(&[1, b'*']);
        wildcard[2..length].copy_from_slice(suffix);
        #[cfg(test)]
        probe();
        match self
            .nodes
            .get(&wildcard[..length])
            .filter(|n| n.metadata.is_original())
        {
            Some(node) => NodeSelection::Wildcard {
                skipped,
                records: &node.records,
            },
            None => NodeSelection::Missing,
        }
    }

    pub(super) fn nodata_cache(&self, name: &DomainName) -> Option<&super::nodata::NodataCache> {
        let mut storage = [0; 255];
        self.nodes
            .get(dns_name_key_into(name, &mut storage))
            .filter(|node| node.metadata.is_original())
            .map(|node| &node.nodata)
    }

    pub(super) fn new(apex: &DomainName, records: &[ResourceRecord]) -> Self {
        let mut nodes = HashMap::<DnsNameKey, Node>::new();
        // NSEC3 and its signatures live in hashed-name metadata space. Keep
        // their raw record indices, but they cannot create original owners or
        // empty nonterminals (RFC 5155 §7.2.8, verified erratum 4622).
        let metadata_owners: HashSet<_> = records
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .map(|record| dns_name_key(&record.name))
            .collect();

        for (index, record) in records.iter().enumerate() {
            let key = dns_name_key(&record.name);
            let metadata = record.rtype == RecordType::NSEC3
                || (record.rtype == RecordType::RRSIG
                    && matches!(&record.rdata, RData::RRSIG(sig) if sig.type_covered == 50)
                    && metadata_owners.contains(&key));
            for suffix in suffixes(&key) {
                if let Some(node) = nodes.get_mut(suffix) {
                    if !metadata {
                        node.metadata.mark_original();
                    }
                } else {
                    let mut node = Node::default();
                    if !metadata {
                        node.metadata.mark_original();
                    }
                    nodes.insert(suffix.into(), node);
                }
            }
            let node = nodes
                .get_mut(key.as_ref())
                .expect("an owner is one of its own suffixes");
            node.records.push(index);
            if record.rtype == RecordType::NS && !record.name.eq_dns(apex) {
                node.metadata.mark_delegation();
            }
            if record.rtype == RecordType::DNAME {
                node.metadata.mark_dname();
            }
        }

        Self { nodes }
    }

    pub(super) fn link_nsec3(
        &mut self,
        apex: &DomainName,
        records: &[ResourceRecord],
        index: &mut super::Nsec3Index,
    ) {
        let original = |node: &Node| node.metadata.is_original();
        index.reserve_nodes(self.nodes.values().filter(|node| original(node)).count());
        for (key, node) in &mut self.nodes {
            if !original(node) {
                continue;
            }
            // Existing owners already hold validated names. Only empty
            // nonterminals need temporary names reconstructed from the key.
            let name = node
                .records
                .first()
                .map(|&i| records[i].name.clone())
                .or_else(|| DomainName::from_wire(key).ok());
            if let Some(name) = name
                && name.is_descendant_of(apex)
            {
                node.metadata.set_nsec3_link(index.register_node(&name));
            }
        }
    }

    #[cfg(test)]
    pub(super) fn metadata_slots(&self) -> (usize, usize, usize) {
        (
            self.nodes.len(),
            std::mem::size_of::<Node>(),
            std::mem::size_of::<NodeMetadata>(),
        )
    }

    pub(super) fn nsec3_link_at_key(&self, key: &[u8]) -> Option<usize> {
        self.nodes.get(key)?.metadata.nsec3_link()
    }

    pub(super) fn records_at(&self, name: &DomainName) -> Option<&[usize]> {
        let mut storage = [0; 255];
        self.records_at_key(dns_name_key_into(name, &mut storage))
    }

    pub(super) fn records_at_key(&self, key: &[u8]) -> Option<&[usize]> {
        #[cfg(test)]
        probe();
        self.nodes
            .get(key)
            .filter(|node| node.metadata.is_original())
            .map(|node| node.records.as_slice())
            .filter(|records| !records.is_empty())
    }

    // Proof assembly must still retrieve signatures at hidden metadata owners.
    pub(super) fn raw_records_at(&self, name: &DomainName) -> Option<&[usize]> {
        let mut storage = [0; 255];
        self.raw_records_at_key(dns_name_key_into(name, &mut storage))
    }

    pub(super) fn raw_records_at_key(&self, key: &[u8]) -> Option<&[usize]> {
        self.nodes
            .get(key)
            .map(|node| node.records.as_slice())
            .filter(|records| !records.is_empty())
    }

    #[cfg(test)]
    pub(super) fn node_exists(&self, name: &DomainName) -> bool {
        let mut storage = [0; 255];
        self.node_exists_key(dns_name_key_into(name, &mut storage))
    }

    pub(super) fn is_exact_delegation_cut(&self, name: &DomainName) -> bool {
        let mut storage = [0; 255];
        let key = dns_name_key_into(name, &mut storage);
        self.outermost_delegation_cut(key)
            .is_some_and(|cut| cut == key)
    }

    pub(super) fn node_exists_key(&self, key: &[u8]) -> bool {
        #[cfg(test)]
        probe();
        self.nodes
            .get(key)
            .is_some_and(|node| node.metadata.is_original())
    }

    pub(super) fn outermost_delegation_cut<'a>(&self, name: &'a [u8]) -> Option<&'a [u8]> {
        suffixes(name)
            .filter(|suffix| {
                #[cfg(test)]
                probe();
                self.nodes
                    .get(*suffix)
                    .is_some_and(|node| node.metadata.is_delegation())
            })
            .last()
    }
}

pub(super) fn records_of_type<'a>(
    records: impl Iterator<Item = &'a ResourceRecord>,
    qtype: QueryType,
) -> Vec<ResourceRecord> {
    records
        .filter(|record| matches_query(record, qtype))
        .cloned()
        .collect()
}

pub(super) fn matches_query(record: &ResourceRecord, qtype: QueryType) -> bool {
    match qtype {
        QueryType::ANY => true,
        QueryType::MAILB => matches!(
            record.rtype,
            RecordType::MB | RecordType::MG | RecordType::MR
        ),
        QueryType::MAILA => matches!(record.rtype, RecordType::MD | RecordType::MF),
        _ => u16::from(record.rtype) == u16::from(qtype),
    }
}

pub(super) fn cname_target(record: &ResourceRecord) -> Option<&DomainName> {
    match &record.rdata {
        RData::CNAME(target) => Some(target),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_tags_preserve_delegation_and_overflow_retains_the_hash_fallback() {
        // The tag word occupies the original bool plus alignment padding.
        assert_eq!(
            std::mem::size_of::<Node>(),
            std::mem::size_of::<(Vec<usize>, bool, super::super::nodata::NodataCache,)>()
        );
        for (delegation, original) in [(false, false), (true, false), (false, true), (true, true)] {
            for (position, expected) in [
                (None, None),
                (Some(1), Some(0)),
                (Some(usize::MAX / 8), Some(usize::MAX / 8 - 1)),
                (Some(usize::MAX / 8 + 1), None),
                (Some(usize::MAX), None),
            ] {
                let mut metadata = NodeMetadata::default();
                if delegation {
                    metadata.mark_delegation();
                }
                if original {
                    metadata.mark_original();
                }
                metadata.set_nsec3_link(position.and_then(NonZeroUsize::new));
                assert_eq!(metadata.is_delegation(), delegation);
                assert_eq!(metadata.is_original(), original);
                assert_eq!(metadata.nsec3_link(), expected);
                metadata.mark_delegation();
                assert!(metadata.is_delegation());
                assert_eq!(metadata.nsec3_link(), expected);
                metadata.set_nsec3_link(None);
                assert!(metadata.is_delegation());
                assert_eq!(metadata.is_original(), original);
                assert_eq!(metadata.nsec3_link(), None);
            }
        }
    }
}

//! Immutable acceleration for coherent NSEC3 rings. Irregular input retains
//! the original selectors, including their source-order and error behavior.
mod prelinked;

use dns::{
    ClassType, DomainName, Nsec3, Nsec3ClosestEncloserProof, Nsec3param, RData, RecordType,
    ResourceRecord,
};

#[derive(Debug)]
pub(in crate::zone) struct Nsec3Index {
    parameters: Nsec3param,
    entries: Vec<Entry>,
    nodes: Vec<prelinked::PrelinkedNode>,
}

#[derive(Debug)]
struct Entry {
    hash: [u8; 20],
    record: usize,
    valid_encloser: bool,
}

pub(in crate::zone) struct BorrowedEncloser<'a> {
    pub labels: &'a [Vec<u8>],
    pub matching_record: usize,
    pub covering_record: usize,
    pub wildcard_cover: Option<Option<usize>>,
}

impl Nsec3Index {
    pub(in crate::zone) fn new(
        apex: &DomainName,
        class: ClassType,
        records: &[ResourceRecord],
    ) -> Option<Self> {
        let mut parameters: Option<Nsec3param> = None;
        let mut entries = Vec::new();
        for (record_index, record) in records.iter().enumerate() {
            if record.rtype != RecordType::NSEC3 || record.class != class {
                continue;
            }
            let RData::NSEC3(nsec3) = &record.rdata else {
                return None;
            };
            // Gate every candidate, even those the closest-encloser helper
            // would ignore: the original direct matching paths differ there.
            if nsec3.hash_algorithm != 1 || nsec3.flags & !Nsec3::OPT_OUT_FLAG != 0 {
                return None;
            }
            let hash = owner_hash(&record.name, apex)?;
            let next: [u8; 20] = nsec3.next_hashed_owner_name.as_slice().try_into().ok()?;
            if let Some(expected) = &parameters {
                if nsec3.iterations != expected.iterations || nsec3.salt != expected.salt {
                    return None;
                }
            } else {
                parameters = Some(Nsec3param {
                    hash_algorithm: 1,
                    flags: 0,
                    iterations: nsec3.iterations,
                    salt: nsec3.salt.clone(),
                });
            }
            let bitmap = nsec3.type_bitmap.as_ref();
            let valid_encloser = !bitmap.is_some_and(|bitmap| {
                bitmap.contains(39) || (bitmap.contains(2) && !bitmap.contains(6))
            });
            entries.push((
                Entry {
                    hash,
                    record: record_index,
                    valid_encloser,
                },
                next,
            ));
        }
        let parameters = parameters?;
        entries.sort_unstable_by_key(|(entry, _)| entry.hash);
        for i in 0..entries.len() {
            let next = &entries[(i + 1) % entries.len()].0;
            if (entries.len() > 1 && entries[i].0.hash == next.hash) || entries[i].1 != next.hash {
                return None;
            }
        }
        Some(Self {
            parameters,
            entries: entries.into_iter().map(|(entry, _)| entry).collect(),
            nodes: Vec::new(),
        })
    }

    fn hash(&self, name: &DomainName) -> Option<[u8; 20]> {
        // The original selector uses the largest chain iteration count as its
        // bound. Coherence makes that exactly this immutable parameter value.
        self.parameters
            .hash_name_fixed(name, self.parameters.iterations)
            .ok()
    }

    fn exact_hash(&self, hash: &[u8; 20]) -> Option<&Entry> {
        self.entries
            .binary_search_by_key(hash, |entry| entry.hash)
            .ok()
            .map(|i| &self.entries[i])
    }

    fn covering_hash(&self, hash: &[u8; 20]) -> Option<&Entry> {
        // Coherent successor links prove this is the unique open interval.
        // Exact endpoints are never covered, including a one-owner ring.
        match self.entries.binary_search_by_key(hash, |entry| entry.hash) {
            Ok(_) => None,
            Err(0) => self.entries.last(),
            Err(i) => self.entries.get(i - 1),
        }
    }

    pub(in crate::zone) fn matching(&self, name: &DomainName) -> Option<usize> {
        self.exact_hash(&self.hash(name)?).map(|entry| entry.record)
    }

    pub(in crate::zone) fn covering(&self, name: &DomainName) -> Option<usize> {
        self.covering_hash(&self.hash(name)?)
            .map(|entry| entry.record)
    }

    pub(in crate::zone) fn closest_encloser(
        &self,
        apex: &DomainName,
        qname: &DomainName,
    ) -> Option<Nsec3ClosestEncloserProof> {
        let proof = self.closest_encloser_labels(apex, qname)?;
        Some(Nsec3ClosestEncloserProof {
            closest_encloser: DomainName::from_labels(proof.labels.to_vec()).ok()?,
            matching_record: proof.matching_record,
            covering_record: proof.covering_record,
        })
    }

    pub(in crate::zone) fn closest_encloser_labels<'a>(
        &self,
        apex: &DomainName,
        qname: &'a DomainName,
    ) -> Option<BorrowedEncloser<'a>> {
        if !qname.is_descendant_of(apex) || qname.as_ref().len() <= apex.as_ref().len() {
            return None;
        }
        let labels = qname.as_ref();
        let mut hashes = self
            .parameters
            .hash_name_suffixes_fixed(qname, self.parameters.iterations);
        let mut next_hash = hashes.next()?.ok()?;
        for dropped in 1..=labels.len() - apex.as_ref().len() {
            let closest_hash = hashes.next()?.ok()?;
            let matching = self.exact_hash(&closest_hash);
            let covering = self.covering_hash(&next_hash);
            next_hash = closest_hash;
            if let (Some(matching), Some(covering)) = (matching, covering) {
                if !matching.valid_encloser {
                    return None; // Preserve immediate failure at this ancestor.
                }
                return Some(BorrowedEncloser {
                    labels: &labels[dropped..],
                    matching_record: matching.record,
                    covering_record: covering.record,
                    wildcard_cover: None,
                });
            }
        }
        None
    }
}

fn owner_hash(owner: &DomainName, apex: &DomainName) -> Option<[u8; 20]> {
    if owner.as_ref().len() != apex.as_ref().len() + 1 || !owner.is_descendant_of(apex) {
        return None;
    }
    let label = &owner.as_ref()[0];
    if label.len() != 32 {
        return None;
    }
    let mut hash = [0; 20];
    let mut accumulator = 0_u16;
    let mut bits = 0;
    let mut written = 0;
    for octet in label {
        let digit = match octet.to_ascii_uppercase() {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'A'..=b'V' => c - b'A' + 10,
            _ => return None,
        };
        accumulator = (accumulator << 5) | u16::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            hash[written] = (accumulator >> bits) as u8;
            written += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(hash)
}

/// Canonical owner order, with unique open intervals proved at snapshot load.
#[derive(Debug)]
pub(in crate::zone) struct NsecIndex {
    entries: Vec<(Vec<u16>, usize)>,
}

impl NsecIndex {
    pub(in crate::zone) fn new(records: &[ResourceRecord], candidates: &[usize]) -> Option<Self> {
        if candidates.is_empty() {
            return None;
        }
        let mut entries = Vec::with_capacity(candidates.len());
        for &record in candidates {
            let RData::NSEC(nsec) = &records[record].rdata else {
                return None;
            };
            entries.push((
                canonical_key(&records[record].name),
                record,
                canonical_key(&nsec.next_domain_name),
            ));
        }
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for i in 0..entries.len() {
            let next = &entries[(i + 1) % entries.len()].0;
            if (entries.len() > 1 && entries[i].0 == *next) || entries[i].2 != *next {
                return None;
            }
        }
        Some(Self {
            entries: entries
                .into_iter()
                .map(|(key, record, _)| (key, record))
                .collect(),
        })
    }

    pub(in crate::zone) fn matching_labels(&self, labels: &[Vec<u8>]) -> Option<usize> {
        let mut storage = [0; 255];
        let key = canonical_labels_into(labels, &mut storage);
        self.entries
            .binary_search_by(|entry| entry.0.as_slice().cmp(key))
            .ok()
            .map(|i| self.entries[i].1)
    }

    pub(in crate::zone) fn covering(&self, name: &DomainName) -> Option<usize> {
        self.covering_labels(name.as_ref())
    }

    pub(in crate::zone) fn covering_labels(&self, labels: &[Vec<u8>]) -> Option<usize> {
        let mut storage = [0; 255];
        self.covering_key(canonical_labels_into(labels, &mut storage))
    }

    pub(in crate::zone) fn covering_wildcard(&self, closest: &[Vec<u8>]) -> Option<usize> {
        let mut storage = [0; 255];
        let length = canonical_labels_into(closest, &mut storage).len();
        if length + 3 > 255 {
            return None;
        }
        // Preserve the same canonical suffix followed by the wildcard label.
        storage[length] = u16::from(b'*') + 1;
        storage[length + 1] = 0;
        self.covering_key(&storage[..length + 2])
    }

    fn covering_key(&self, key: &[u16]) -> Option<usize> {
        match self
            .entries
            .binary_search_by(|entry| entry.0.as_slice().cmp(key))
        {
            Ok(_) => None,
            Err(0) => self.entries.last().map(|entry| entry.1),
            Err(i) => Some(self.entries[i - 1].1),
        }
    }
}

fn canonical_key(name: &DomainName) -> Vec<u16> {
    let mut storage = [0; 255];
    canonical_labels_into(name.as_ref(), &mut storage).to_vec()
}

fn canonical_labels_into<'a>(labels: &[Vec<u8>], key: &'a mut [u16; 255]) -> &'a [u16] {
    // RFC 4034 orders labels from the root, and compares their octets before
    // their lengths. A zero separator and octets shifted into 1..=256 retain
    // that order for binary labels as well as ASCII. A valid DomainName is
    // at most 255 wire octets, so lookup keys fit without a heap allocation.
    let mut length = 0;
    for label in labels.iter().rev() {
        for octet in label {
            key[length] = u16::from(octet.to_ascii_lowercase()) + 1;
            length += 1;
        }
        key[length] = 0;
        length += 1;
    }
    &key[..length]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_keys_match_dnssec_order_for_binary_case_and_prefix_labels() {
        let mut names = vec![DomainName::root()];
        for labels in [
            vec![vec![0]],
            vec![vec![255]],
            vec![b"a".to_vec()],
            vec![b"AA".to_vec()],
            vec![b"z".to_vec()],
            vec![b"A".to_vec()],
            vec![b"a\0".to_vec()],
            vec![b"a".to_vec(), b"example".to_vec()],
            vec![b"*".to_vec(), b"EXAMPLE".to_vec()],
            vec![b"z".to_vec(), b"a".to_vec(), b"example".to_vec()],
        ] {
            names.push(DomainName::from_labels(labels).unwrap());
        }
        names.push(
            DomainName::from_labels(vec![
                vec![255; 63],
                vec![0; 63],
                vec![b'A'; 63],
                vec![b'z'; 61],
            ])
            .unwrap(),
        );
        for a in &names {
            for b in &names {
                assert_eq!(canonical_key(a).cmp(&canonical_key(b)), a.canonical_cmp(b));
            }
        }
    }
}

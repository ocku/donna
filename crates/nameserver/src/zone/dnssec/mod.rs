mod borrowed;
mod denial_index;
mod nsec3;
mod positive;
mod wildcard;
pub(super) use denial_index::{Nsec3Index, NsecIndex};

use std::cmp::Ordering;

use smallvec::SmallVec;

use dns::{DomainName, RData, RecordType, ResourceRecord};

use super::{Zone, response};

/// The SOA and its signatures are invariant within an immutable zone snapshot.
/// Keep their original order and trimmed negative TTLs, including legacy SIGs.
#[derive(Debug, Default)]
pub(super) struct NegativeResponsePrefix {
    records: Vec<ResourceRecord>,
    ordinary_len: usize,
}

impl Zone {
    pub(crate) fn negative_response_soa(&self) -> ResourceRecord {
        let mut soa = self.soa.clone();
        soa.ttl = soa.ttl.min(self.soa_minimum());
        soa
    }

    pub(super) fn build_negative_response_prefix(&self) -> NegativeResponsePrefix {
        let soa = self.negative_response_soa();
        let soa_ttl = soa.ttl;
        let mut records = vec![soa];
        records.extend(
            self.signatures_covering(&self.apex, 6)
                .map(|mut signature| {
                    // RFC 2308 §3 trims the SOA signature along with the SOA used
                    // to carry the negative cache lifetime.
                    signature.ttl = signature.ttl.min(soa_ttl);
                    signature
                }),
        );

        let ordinary_len = records.len();
        records.extend(
            self.rrsigs_covering(&self.apex, u16::from(RecordType::SOA))
                .map(|mut signature| {
                    signature.ttl = signature.ttl.min(soa_ttl);
                    signature
                }),
        );
        NegativeResponsePrefix {
            records,
            ordinary_len,
        }
    }

    /// Builds the RFC 2308 authority section for an authoritative negative.
    ///
    /// RFC 2308 §3 requires a signed RFC 2065 zone to return the SOA, its SIG,
    /// and the appropriate NXT proof. For current DNSSEC, DO requests also
    /// receive the SOA RRSIG and the configured NSEC or NSEC3 denial proof.
    pub(crate) fn negative_response_authorities(
        &self,
        proof_owner: &DomainName,
        expanded_owner: &DomainName,
        name_error: bool,
        dnssec_ok: bool,
    ) -> Vec<ResourceRecord> {
        let prefix = &self.negative_prefix;
        let records = if dnssec_ok {
            &prefix.records[..]
        } else {
            &prefix.records[..prefix.ordinary_len]
        };
        // Signed NODATA normally carries SOA/proof and their two signatures.
        // Reserve that small prefix once; larger and legacy sets still grow.
        let mut authorities = Vec::with_capacity(records.len().max(if dnssec_ok { 4 } else { 1 }));
        authorities.extend_from_slice(records);

        if dnssec_ok {
            self.append_current_denial_proofs(&mut authorities, proof_owner, name_error);
            if !name_error && !proof_owner.eq_dns(expanded_owner) {
                // A wildcard's type bitmap denies the type, not the expanded
                // QNAME's existence. Preserve both names through proof selection.
                self.append_wildcard_nodata_proofs(&mut authorities, expanded_owner, proof_owner);
            }
        }

        let proof = if name_error {
            self.nxt_preceding(proof_owner)
        } else {
            self.nxt_records
                .iter()
                .map(|&i| &self.records[i])
                .find(|record| record.name.eq_dns(proof_owner))
        };
        if let Some(proof) = proof {
            authorities.push(proof.clone());
            authorities.extend(self.signatures_covering(&proof.name, 30));
        }
        authorities
    }

    pub(crate) fn append_rrsigs_for(&self, records: &mut Vec<ResourceRecord>) {
        let covered = records
            .iter()
            .filter(|record| record.rtype != RecordType::RRSIG)
            .map(|record| (record.name.clone(), u16::from(record.rtype)))
            .collect::<Vec<_>>();
        for (owner, covered_type) in covered {
            for mut signature in
                self.rrsig_candidate_indices(&owner)
                    .into_iter()
                    .filter_map(|index| {
                        let record = &self.records[index];
                        let RData::RRSIG(rrsig) = &record.rdata else {
                            return None;
                        };
                        if record.rtype != RecordType::RRSIG
                            || record.class != self.class
                            || rrsig.type_covered != covered_type
                        {
                            return None;
                        }
                        let source_matches =
                            rrsig_source_matches(&record.name, &owner, rrsig.labels);
                        source_matches.then(|| record.clone())
                    })
            {
                signature.name = owner.clone();
                if !response::contains_record(records, &signature) {
                    records.push(signature);
                }
            }
        }
    }

    /// Select signatures at the actual answer source. An ancestor wildcard is
    /// not an alternative synthesis source (RFC 4592 section 3.3.1).
    fn rrsig_candidate_indices(&self, owner: &DomainName) -> SmallVec<[usize; 8]> {
        let mut storage = [0; 255];
        let key = crate::name::dns_name_key_into(owner, &mut storage);
        let indices = match self.index.select(key) {
            super::lookup::NodeSelection::Exact(indices)
            | super::lookup::NodeSelection::Dname(indices)
            | super::lookup::NodeSelection::Wildcard {
                records: indices, ..
            }
            | super::lookup::NodeSelection::Delegation {
                records: indices, ..
            } => indices,
            super::lookup::NodeSelection::Missing => return SmallVec::new(),
        };
        indices
            .iter()
            .copied()
            .filter(|&index| self.records[index].rtype == RecordType::RRSIG)
            .collect()
    }

    pub(crate) fn append_referral_dnssec(&self, authorities: &mut Vec<ResourceRecord>) {
        let Some(delegation) = authorities
            .iter()
            .find(|record| record.rtype == RecordType::NS)
            .map(|record| record.name.clone())
        else {
            return;
        };
        let ds_records = self
            .records_at(&delegation)
            .into_iter()
            .filter(|record| record.rtype == RecordType::DS)
            .collect::<Vec<_>>();
        if !ds_records.is_empty() {
            for record in ds_records {
                if !response::contains_record(authorities, &record) {
                    authorities.push(record);
                }
            }
            for signature in self.rrsigs_covering(&delegation, u16::from(RecordType::DS)) {
                if !response::contains_record(authorities, &signature) {
                    authorities.push(signature);
                }
            }
            return;
        }

        if self.has_nsec3param {
            self.append_nsec3_delegation_proof(authorities, &delegation);
        } else {
            self.append_nsec_proofs(authorities, &delegation, false);
        }
    }

    fn append_current_denial_proofs(
        &self,
        authorities: &mut Vec<ResourceRecord>,
        proof_owner: &DomainName,
        name_error: bool,
    ) {
        if self.has_nsec3param {
            if !name_error && self.index.is_exact_delegation_cut(proof_owner) {
                self.append_nsec3_delegation_proof(authorities, proof_owner);
            } else {
                self.append_nsec3_proofs(authorities, proof_owner, name_error);
            }
        } else {
            self.append_nsec_proofs(authorities, proof_owner, name_error);
        }
    }

    fn append_nsec_proofs(
        &self,
        authorities: &mut Vec<ResourceRecord>,
        proof_owner: &DomainName,
        name_error: bool,
    ) {
        self.append_proofs_with_rrsigs(authorities, self.nsec_proof_refs(proof_owner, name_error));
    }

    fn nsec_proof_refs(
        &self,
        proof_owner: &DomainName,
        name_error: bool,
    ) -> SmallVec<[&ResourceRecord; 3]> {
        if !name_error {
            // The owner index has the same source order as nsec_records. Its
            // membership check retains class and delegation visibility, even
            // for irregular rings and private defensive snapshots. No exact
            // match here also proves that the ring's exact search would fail.
            if let Some(record) = self
                .index
                .records_at(proof_owner)
                .into_iter()
                .flatten()
                .copied()
                .find(|index| {
                    self.records[*index].rtype == RecordType::NSEC
                        && self.nsec_records.binary_search(index).is_ok()
                })
            {
                return smallvec::smallvec![&self.records[record]];
            }
        }
        if let Some(index) = &self.nsec_index {
            let mut selected = SmallVec::<[usize; 3]>::new();
            if name_error {
                if let Some(closest) = self.closest_encloser_labels(proof_owner)
                    && closest.iter().map(|label| label.len() + 1).sum::<usize>() + 3 <= 255
                {
                    if let Some(record) = index.matching_labels(closest) {
                        selected.push(record);
                    }
                    let labels = proof_owner.as_ref();
                    if labels.len() > closest.len()
                        && let Some(record) =
                            index.covering_labels(&labels[labels.len() - closest.len() - 1..])
                        && !selected.contains(&record)
                    {
                        selected.push(record);
                    }
                    if let Some(record) = index.covering_wildcard(closest)
                        && !selected.contains(&record)
                    {
                        selected.push(record);
                    }
                }
            } else if let Some(record) = index.covering(proof_owner)
                && matches!(&self.records[record].rdata, RData::NSEC(nsec)
                    if !nsec.next_domain_name.eq_dns(proof_owner) && nsec.next_domain_name.is_descendant_of(proof_owner))
            {
                selected.push(record);
            }
            // Keep the existing closest/next-closer/wildcard order for NSEC.
            let proofs = selected.into_iter().map(|i| &self.records[i]);
            return proofs.collect();
        }
        let nsecs = || self.nsecs();
        let mut proofs = SmallVec::<[&ResourceRecord; 3]>::new();
        if name_error {
            if let Some(wildcard) = self.wildcard_at_closest_encloser(proof_owner) {
                let closest_encloser = DomainName::from_labels(wildcard.as_ref()[1..].to_vec())
                    .expect("a wildcard suffix is a valid domain name");
                if let Some(record) = nsecs().find(|record| record.name.eq_dns(&closest_encloser)) {
                    proofs.push(record);
                }
                if let Some(next_closer) = next_closer_name(proof_owner, &closest_encloser)
                    && let Some(record) = nsecs().find(|record| {
                        matches!(&record.rdata, RData::NSEC(nsec) if nsec.covers_name(&record.name, &next_closer))
                    })
                    && !proofs.iter().any(|existing| existing.eq_dns(record))
                {
                    proofs.push(record);
                }
                if let Some(record) = nsecs().find(|record| {
                    matches!(&record.rdata, RData::NSEC(nsec) if nsec.covers_name(&record.name, &wildcard))
                }) && !proofs.iter().any(|existing| existing.eq_dns(record))
                {
                    proofs.push(record);
                }
            }
        } else if let Some(record) = nsecs().find(|record| {
            matches!(&record.rdata, RData::NSEC(nsec)
                if !nsec.next_domain_name.eq_dns(proof_owner)
                    && nsec.next_domain_name.is_descendant_of(proof_owner)
                    && nsec.covers_name(&record.name, proof_owner))
        }) {
            // No NSEC is stored at an empty nonterminal. An interval ending
            // at a strict descendant proves that the empty name exists.
            proofs.push(record);
        }
        proofs
    }

    fn append_proofs_with_rrsigs<'a>(
        &self,
        authorities: &mut Vec<ResourceRecord>,
        proofs: impl IntoIterator<Item = &'a ResourceRecord>,
    ) {
        for proof in proofs {
            if !response::contains_record(authorities, proof) {
                authorities.push(proof.clone());
            }
            for signature in self.rrsigs_covering(&proof.name, u16::from(proof.rtype)) {
                if !response::contains_record(authorities, &signature) {
                    authorities.push(signature);
                }
            }
        }
    }

    fn signatures_covering<'a>(
        &'a self,
        owner: &'a DomainName,
        covered_type: u16,
    ) -> impl Iterator<Item = ResourceRecord> + 'a {
        self.signatures_covering_refs(owner, covered_type).cloned()
    }

    fn signatures_covering_refs<'a>(
        &'a self,
        owner: &'a DomainName,
        covered_type: u16,
    ) -> impl Iterator<Item = &'a ResourceRecord> + 'a {
        self.index
            .raw_records_at(owner)
            .into_iter()
            .flatten()
            .map(|&index| &self.records[index])
            .filter(move |record| {
                let RData::SIG(sig) = &record.rdata else {
                    return false;
                };
                record.rtype == RecordType::SIG
                    && record.class == self.class
                    && record.name.eq_dns(owner)
                    && sig.type_covered == covered_type
            })
    }

    fn rrsigs_covering<'a>(
        &'a self,
        owner: &'a DomainName,
        covered_type: u16,
    ) -> impl Iterator<Item = ResourceRecord> + 'a {
        self.rrsigs_covering_refs(owner, covered_type).cloned()
    }

    fn rrsigs_covering_refs<'a>(
        &'a self,
        owner: &'a DomainName,
        covered_type: u16,
    ) -> impl Iterator<Item = &'a ResourceRecord> + 'a {
        self.index
            .raw_records_at(owner)
            .into_iter()
            .flatten()
            .map(|&index| &self.records[index])
            .filter(move |record| {
                let RData::RRSIG(rrsig) = &record.rdata else {
                    return false;
                };
                record.rtype == RecordType::RRSIG
                    && record.class == self.class
                    && record.name.eq_dns(owner)
                    && rrsig.type_covered == covered_type
            })
    }

    fn nxt_preceding(&self, qname: &DomainName) -> Option<&ResourceRecord> {
        let candidates = || self.nxt_records.iter().map(|&i| &self.records[i]);
        candidates()
            .filter(|record| record.name.canonical_cmp(qname) == Ordering::Less)
            .max_by(|left, right| left.name.canonical_cmp(&right.name))
            // The last NXT wraps to the zone apex and proves names which sort
            // before the first owner in the zone.
            .or_else(|| candidates().max_by(|left, right| left.name.canonical_cmp(&right.name)))
    }

    fn nsecs(&self) -> impl Iterator<Item = &ResourceRecord> {
        self.nsec_records.iter().map(|&i| &self.records[i])
    }
}

fn rrsig_source_matches(source: &DomainName, owner: &DomainName, labels: u8) -> bool {
    if source.eq_dns(owner) {
        return true;
    }
    let labels = usize::from(labels);
    let owner = owner.as_ref();
    let source = source.as_ref();
    // Compare the wildcard source directly. If it matches, its validated
    // DomainName also proves that constructing that wildcard would fit the
    // wire limit; unrelated signatures need no temporary label vectors.
    labels < owner.len()
        && source.len() == labels + 1
        && source[0] == b"*"
        && source[1..]
            .iter()
            .zip(&owner[owner.len() - labels..])
            .all(|(source, owner)| source.eq_ignore_ascii_case(owner))
}

fn wildcard_name(closest_encloser: &DomainName) -> Option<DomainName> {
    let mut labels = Vec::with_capacity(closest_encloser.as_ref().len() + 1);
    labels.push(b"*".to_vec());
    labels.extend_from_slice(closest_encloser.as_ref());
    DomainName::from_labels(labels).ok()
}

fn next_closer_name(name: &DomainName, closest_encloser: &DomainName) -> Option<DomainName> {
    if !name.is_descendant_of(closest_encloser)
        || name.as_ref().len() <= closest_encloser.as_ref().len()
    {
        return None;
    }
    let first_label = name.as_ref().len() - closest_encloser.as_ref().len() - 1;
    DomainName::from_labels(name.as_ref()[first_label..].to_vec()).ok()
}

#[cfg(test)]
mod tests;

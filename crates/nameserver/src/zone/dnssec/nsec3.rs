use dns::{DomainName, RData, RecordType, ResourceRecord, find_nsec3_closest_encloser};

use super::wildcard_name;
use crate::zone::Zone;

impl Zone {
    pub(super) fn append_nsec3_proofs(
        &self,
        authorities: &mut Vec<ResourceRecord>,
        proof_owner: &DomainName,
        name_error: bool,
    ) {
        if let Some(index) = &self.nsec3_index {
            let mut selected = Vec::with_capacity(3);
            if name_error {
                selected.extend(index.name_error_proof_indices(
                    &self.apex,
                    proof_owner,
                    &self.index,
                ));
            } else if let Some(record) = index.matching_linked(proof_owner, &self.index) {
                selected.push(record);
            }
            self.append_indexed_nsec3_proofs(authorities, selected);
            return;
        }
        let records = self
            .records
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3 && record.class == self.class)
            .cloned()
            .collect::<Vec<_>>();
        let maximum_iterations = records
            .iter()
            .filter_map(|record| match &record.rdata {
                RData::NSEC3(nsec3) => Some(nsec3.iterations),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let mut indexes = Vec::new();
        if name_error {
            let Ok(proof) = find_nsec3_closest_encloser(
                &records,
                &self.apex,
                self.class,
                proof_owner,
                maximum_iterations,
            ) else {
                return;
            };
            indexes.extend([proof.matching_record, proof.covering_record]);
            if let Some(wildcard) = wildcard_name(&proof.closest_encloser)
                && let Some(index) = records.iter().position(|record| {
                    matches!(&record.rdata, RData::NSEC3(nsec3) if nsec3
                        .covers_name(&record.name, &self.apex, &wildcard, maximum_iterations)
                        .unwrap_or(false))
                })
            {
                indexes.push(index);
            }
        } else if let Some(index) = records.iter().position(|record| {
            matches!(&record.rdata, RData::NSEC3(nsec3) if nsec3
                .matches_name(&record.name, &self.apex, proof_owner, maximum_iterations)
                .unwrap_or(false))
        }) {
            indexes.push(index);
        }
        indexes.sort_unstable();
        indexes.dedup();
        let proofs = indexes.into_iter().filter_map(|index| records.get(index));
        self.append_proofs_with_rrsigs(authorities, proofs);
    }

    pub(super) fn append_nsec3_delegation_proof(
        &self,
        authorities: &mut Vec<ResourceRecord>,
        delegation: &DomainName,
    ) {
        if let Some(index) = &self.nsec3_index {
            let selected = if let Some(record) = index.matching_linked(delegation, &self.index) {
                vec![record]
            } else if let Some(proof) =
                index.closest_encloser_linked(&self.apex, delegation, &self.index)
                && matches!(&self.records[proof.covering_record].rdata, RData::NSEC3(nsec3) if nsec3.opt_out())
            {
                vec![proof.matching_record, proof.covering_record]
            } else {
                Vec::new()
            };
            self.append_indexed_nsec3_proofs(authorities, selected);
            return;
        }
        let records = self
            .records
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3 && record.class == self.class)
            .cloned()
            .collect::<Vec<_>>();
        let maximum_iterations = records
            .iter()
            .filter_map(|record| match &record.rdata {
                RData::NSEC3(nsec3) => Some(nsec3.iterations),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        if let Some(proof) = records.iter().find(|record| {
            matches!(&record.rdata, RData::NSEC3(nsec3) if nsec3
                .matches_name(&record.name, &self.apex, delegation, maximum_iterations)
                .unwrap_or(false))
        }) {
            self.append_proofs_with_rrsigs(authorities, [proof]);
            return;
        }

        // RFC 5155 sections 7.2.4 and 7.2.7 require the complete closest
        // provable encloser proof, not merely an opt-out covering interval.
        let Ok(proof) = find_nsec3_closest_encloser(
            &records,
            &self.apex,
            self.class,
            delegation,
            maximum_iterations,
        ) else {
            return;
        };
        if !matches!(&records[proof.covering_record].rdata, RData::NSEC3(nsec3) if nsec3.opt_out())
        {
            return;
        }
        let mut indexes = vec![proof.matching_record, proof.covering_record];
        indexes.sort_unstable();
        indexes.dedup();
        let proofs = indexes.into_iter().map(|index| &records[index]);
        self.append_proofs_with_rrsigs(authorities, proofs);
    }

    pub(super) fn append_indexed_nsec3_proofs(
        &self,
        authorities: &mut Vec<ResourceRecord>,
        mut selected: Vec<usize>,
    ) {
        // The old filtered scan uses zone storage order, not hash order.
        selected.sort_unstable();
        selected.dedup();
        let proofs = selected.into_iter().map(|index| &self.records[index]);
        self.append_proofs_with_rrsigs(authorities, proofs);
    }
}

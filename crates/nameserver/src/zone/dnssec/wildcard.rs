use dns::{DomainName, RData, RecordType, ResourceRecord, find_nsec3_closest_encloser};

use super::next_closer_name;
use crate::zone::Zone;

impl Zone {
    pub(crate) fn append_wildcard_denial(
        &self,
        answers: &[ResourceRecord],
        authorities: &mut Vec<ResourceRecord>,
    ) {
        let Some((expanded_owner, closest_encloser, needs_closest_proof)) =
            answers.iter().find_map(|record| {
                let RData::RRSIG(rrsig) = &record.rdata else {
                    return None;
                };
                let labels = usize::from(rrsig.labels);
                let owner_labels = record.name.as_ref();
                (labels < owner_labels.len()).then(|| {
                    let closest = DomainName::from_labels(
                        owner_labels[owner_labels.len() - labels..].to_vec(),
                    )
                    .expect("an expanded owner suffix is a valid domain name");
                    // RFC 5155 sections 7.2.6 and 8.8: the signed expanded
                    // RRset already demonstrates its generating wildcard's
                    // ancestor. Keep the conservative proof for an unpaired or
                    // foreign signature; NODATA never takes this shortcut.
                    let signed_answer = record.rtype == RecordType::RRSIG
                        && record.class == self.class
                        && rrsig.signer_name.eq_dns(&self.apex)
                        && answers.iter().any(|answer| {
                            answer.class == record.class
                                && answer.name.eq_dns(&record.name)
                                && u16::from(answer.rtype) == rrsig.type_covered
                        });
                    (record.name.clone(), closest, !signed_answer)
                })
            })
        else {
            return;
        };
        self.append_wildcard_expansion_proofs(
            authorities,
            &expanded_owner,
            &closest_encloser,
            needs_closest_proof,
        );
    }

    pub(super) fn append_wildcard_nodata_proofs(
        &self,
        authorities: &mut Vec<ResourceRecord>,
        expanded_owner: &DomainName,
        wildcard_owner: &DomainName,
    ) {
        let closest_encloser = DomainName::from_labels(wildcard_owner.as_ref()[1..].to_vec())
            .expect("a wildcard suffix is a valid domain name");
        // RFC 4035 section 3.1.3.4 and RFC 5155 section 7.2.5 require
        // expansion denial in addition to the matching wildcard type bitmap.
        self.append_wildcard_expansion_proofs(authorities, expanded_owner, &closest_encloser, true);
    }

    fn append_wildcard_expansion_proofs(
        &self,
        authorities: &mut Vec<ResourceRecord>,
        expanded_owner: &DomainName,
        closest_encloser: &DomainName,
        needs_closest_proof: bool,
    ) {
        if self.has_nsec3param {
            if let Some(index) = &self.nsec3_index {
                if let Some(proof) =
                    index.closest_encloser_labels_linked(&self.apex, expanded_owner, &self.index)
                    && proof.labels.len() == closest_encloser.as_ref().len()
                    && proof
                        .labels
                        .iter()
                        .zip(closest_encloser.as_ref())
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
                {
                    let mut selected = vec![proof.covering_record];
                    if needs_closest_proof {
                        selected.push(proof.matching_record);
                    }
                    self.append_indexed_nsec3_proofs(authorities, selected);
                }
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
            if let Ok(proof) = find_nsec3_closest_encloser(
                &records,
                &self.apex,
                self.class,
                expanded_owner,
                maximum_iterations,
            ) && proof.closest_encloser.eq_dns(closest_encloser)
            {
                let mut indexes = vec![proof.covering_record];
                if needs_closest_proof {
                    indexes.push(proof.matching_record);
                }
                indexes.sort_unstable();
                indexes.dedup();
                let proofs = indexes.into_iter().filter_map(|index| records.get(index));
                self.append_proofs_with_rrsigs(authorities, proofs);
            }
            return;
        }

        let Some(next_closer) = next_closer_name(expanded_owner, closest_encloser) else {
            return;
        };
        if let Some(index) = &self.nsec_index {
            if let Some(record) = index.covering(&next_closer) {
                self.append_proofs_with_rrsigs(authorities, [&self.records[record]]);
            }
            return;
        }
        let proof = self.nsecs().find(|record| {
            matches!(&record.rdata, RData::NSEC(nsec)
                if nsec.covers_name(&record.name, &next_closer))
        });
        if let Some(proof) = proof {
            self.append_proofs_with_rrsigs(authorities, [proof]);
        }
    }
}

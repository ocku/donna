use super::*;
use crate::zone::PositiveRecordRefs;

impl Zone {
    pub(crate) fn append_positive_rrsig_refs<'a>(
        &'a self,
        answers: &mut PositiveRecordRefs<'a>,
        source_indices: &[usize],
    ) {
        let covered = answers
            .iter()
            .filter(|(record, _)| record.rtype != RecordType::RRSIG)
            .map(|&(record, owner)| (owner, u16::from(record.rtype)))
            .collect::<SmallVec<[_; 8]>>();
        for (owner, covered_type) in covered {
            for &index in source_indices {
                let record = &self.records[index];
                let RData::RRSIG(rrsig) = &record.rdata else {
                    continue;
                };
                if record.rtype != RecordType::RRSIG
                    || record.class != self.class
                    || rrsig.type_covered != covered_type
                    || !rrsig_source_matches(&record.name, owner, rrsig.labels)
                {
                    continue;
                }
                if !answers.iter().any(|&(previous, previous_owner)| {
                    previous.rtype == record.rtype
                        && previous.class == record.class
                        && previous_owner.eq_dns(owner)
                        && previous.rdata == record.rdata
                }) {
                    answers.push((record, owner));
                }
            }
        }
    }

    pub(crate) fn positive_authority_refs<'a>(
        &'a self,
        answers: &PositiveRecordRefs<'_>,
    ) -> Option<SmallVec<[&'a ResourceRecord; 8]>> {
        let mut authorities = SmallVec::new();
        let Some((expanded, closest, needs_closest)) =
            answers.iter().find_map(|&(record, owner)| {
                let RData::RRSIG(sig) = &record.rdata else {
                    return None;
                };
                let labels = usize::from(sig.labels);
                (labels < owner.as_ref().len()).then(|| {
                    let signed = record.rtype == RecordType::RRSIG
                        && record.class == self.class
                        && sig.signer_name.eq_dns(&self.apex)
                        && answers.iter().any(|&(answer, answer_owner)| {
                            answer.class == record.class
                                && answer_owner.eq_dns(owner)
                                && u16::from(answer.rtype) == sig.type_covered
                        });
                    (
                        owner,
                        &owner.as_ref()[owner.as_ref().len() - labels..],
                        !signed,
                    )
                })
            })
        else {
            return Some(authorities);
        };
        let mut selected = SmallVec::<[usize; 2]>::new();
        if self.has_nsec3param {
            let index = self.nsec3_index.as_ref()?;
            if let Some(proof) =
                index.closest_encloser_labels_linked(&self.apex, expanded, &self.index)
                && proof.labels.len() == closest.len()
                && proof
                    .labels
                    .iter()
                    .zip(closest)
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                selected.push(proof.covering_record);
                if needs_closest {
                    selected.push(proof.matching_record);
                }
                selected.sort_unstable();
                selected.dedup();
            }
        } else {
            let index = self.nsec_index.as_ref()?;
            let labels = expanded.as_ref();
            if let Some(record) = index.covering_labels(&labels[labels.len() - closest.len() - 1..])
            {
                selected.push(record);
            }
        }
        for index in selected {
            let proof = &self.records[index];
            for record in std::iter::once(proof)
                .chain(self.rrsigs_covering_refs(&proof.name, u16::from(proof.rtype)))
            {
                if !authorities.iter().any(|previous: &&ResourceRecord| {
                    previous.rtype == record.rtype
                        && previous.class == record.class
                        && previous.name.eq_dns(&record.name)
                        && previous.rdata == record.rdata
                }) {
                    authorities.push(record);
                }
            }
        }
        Some(authorities)
    }
}

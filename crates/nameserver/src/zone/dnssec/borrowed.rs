use super::*;

impl Zone {
    /// Borrows the same ordered negative records from an immutable snapshot.
    /// Irregular NSEC3, delegation opt-out and legacy NXT
    /// retain the structured selector, including all of its fallback behavior.
    pub(crate) fn negative_authority_refs(
        &self,
        proof_owner: &DomainName,
        expanded_owner: &DomainName,
        name_error: bool,
        dnssec_ok: bool,
    ) -> Option<SmallVec<[&ResourceRecord; 8]>> {
        if !self.nxt_records.is_empty() {
            return None;
        }
        let prefix = &self.negative_prefix;
        let records = if dnssec_ok {
            &prefix.records[..]
        } else {
            &prefix.records[..prefix.ordinary_len]
        };
        let mut authorities = SmallVec::<[&ResourceRecord; 8]>::new();
        fn push<'a>(
            authorities: &mut SmallVec<[&'a ResourceRecord; 8]>,
            record: &'a ResourceRecord,
        ) {
            if !authorities.iter().any(|previous| {
                previous.rtype == record.rtype
                    && previous.class == record.class
                    && previous.name.eq_dns(&record.name)
                    && previous.rdata == record.rdata
            }) {
                authorities.push(record);
            }
        }
        for record in records {
            push(&mut authorities, record);
        }
        if !dnssec_ok {
            return Some(authorities);
        }
        let proofs = if self.has_nsec3param {
            let index = self.nsec3_index.as_ref()?;
            if !name_error && self.index.is_exact_delegation_cut(proof_owner) {
                return None;
            }
            let mut selected = SmallVec::<[usize; 3]>::new();
            if name_error {
                selected.extend(index.name_error_proof_indices(
                    &self.apex,
                    proof_owner,
                    &self.index,
                ));
            } else if let Some(record) = index.matching_linked(proof_owner, &self.index) {
                selected.push(record);
            }
            selected.sort_unstable();
            selected.dedup();
            selected
                .into_iter()
                .map(|i| &self.records[i])
                .collect::<SmallVec<[_; 3]>>()
        } else {
            self.nsec_proof_refs(proof_owner, name_error)
        };
        for proof in proofs {
            push(&mut authorities, proof);
            for signature in self.rrsigs_covering_refs(&proof.name, u16::from(proof.rtype)) {
                push(&mut authorities, signature);
            }
        }
        if !name_error && !proof_owner.eq_dns(expanded_owner) {
            // Keep the ordinary selector's two-stage order: wildcard bitmap,
            // then expansion witnesses. Never reuse a denial for another QNAME.
            let closest = proof_owner.as_ref().get(1..)?;
            let mut selected = SmallVec::<[usize; 2]>::new();
            if self.has_nsec3param {
                let index = self.nsec3_index.as_ref()?;
                if let Some(proof) =
                    index.closest_encloser_labels_linked(&self.apex, expanded_owner, &self.index)
                    && proof.labels.len() == closest.len()
                    && proof
                        .labels
                        .iter()
                        .zip(closest)
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
                {
                    // RFC 5155 section 7.2.5: NODATA requires both witnesses.
                    selected.extend([proof.matching_record, proof.covering_record]);
                    selected.sort_unstable();
                    selected.dedup();
                }
            } else {
                let index = self.nsec_index.as_ref()?;
                let labels = expanded_owner.as_ref();
                if labels.len() > closest.len()
                    && labels[labels.len() - closest.len()..]
                        .iter()
                        .zip(closest)
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
                    && let Some(record) =
                        index.covering_labels(&labels[labels.len() - closest.len() - 1..])
                {
                    selected.push(record);
                }
            }
            for index in selected {
                let proof = &self.records[index];
                push(&mut authorities, proof);
                for signature in self.rrsigs_covering_refs(&proof.name, u16::from(proof.rtype)) {
                    push(&mut authorities, signature);
                }
            }
        }
        Some(authorities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{IntoWire, master::MasterFile};

    #[test]
    fn borrowed_wildcard_denials_match_structured_selection_and_fallback() {
        for source in [
            include_str!("../tests/fixtures/bind-nsec.zone"),
            include_str!("../tests/fixtures/bind-nsec3.zone"),
        ] {
            let apex = DomainName::from_dotted("example.test.").unwrap();
            let mut zone =
                Zone::from_master(apex.clone(), MasterFile::parse(source, Some(apex)).unwrap())
                    .unwrap();
            let mut reference = Zone::new(
                zone.apex.clone(),
                zone.class,
                zone.records.clone(),
                zone.soa.clone(),
            );
            // The oracle retains the original full scans and proof helper.
            reference.nsec_index = None;
            reference.nsec3_index = None;
            let wildcard = DomainName::from_dotted("*.wild.example.test.").unwrap();
            for owner in [
                "m.wild.example.test.",
                "p.q.wild.example.test.",
                "P.Q.WILD.EXAMPLE.TEST.",
                "outside.invalid.",
            ] {
                let expanded = DomainName::from_dotted(owner).unwrap();
                for dnssec_ok in [false, true] {
                    let actual = zone
                        .negative_authority_refs(&wildcard, &expanded, false, dnssec_ok)
                        .unwrap();
                    let mut expected = Vec::new();
                    for record in reference
                        .negative_response_authorities(&wildcard, &expanded, false, dnssec_ok)
                    {
                        if !response::contains_record(&expected, &record) {
                            expected.push(record);
                        }
                    }
                    assert_eq!(actual.len(), expected.len());
                    for (actual, expected) in actual.iter().zip(&expected) {
                        assert_eq!(actual.into_wire().unwrap(), expected.into_wire().unwrap());
                    }
                }
            }
            zone.nsec_index = None;
            zone.nsec3_index = None;
            let expanded = DomainName::from_dotted("p.q.wild.example.test.").unwrap();
            assert!(
                zone.negative_authority_refs(&wildcard, &expanded, false, true)
                    .is_none()
            );
        }
    }
}

use super::authentication::{next_closer_name, unsafe_closest_encloser_bitmap, wildcard_name};
use super::*;

/// Reject parent-side evidence at or below a delegation or a DNAME owner.
fn has_unsafe_ancestor(
    qname: &DomainName,
    records: &[(usize, &ResourceRecord, &crate::Nsec)],
) -> bool {
    records.iter().any(|(_, record, nsec)| {
        qname.is_descendant_of(&record.name)
            && unsafe_closest_encloser_bitmap(nsec.type_bitmap.codes())
    })
}

impl AuthenticatedDnskeySet {
    /// Validates an RFC 4035 NSEC name-error proof, including denial of a
    /// wildcard at the closest encloser.
    pub fn validate_nsec_name_error(
        &self,
        qname: &DomainName,
        nsec_records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
    ) -> DnssecValidation<AuthenticatedDenial> {
        if !qname.is_descendant_of(&self.zone) {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        }
        let usable = nsec_records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| match &record.rdata {
                RData::NSEC(nsec)
                    if record.rtype == RecordType::NSEC
                        && record.class == self.class
                        && record.name.is_descendant_of(&self.zone)
                        && nsec.next_domain_name.is_descendant_of(&self.zone) =>
                {
                    Some((index, record, nsec))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let qlabels = qname.as_ref();
        let zone_labels = self.zone.as_ref().len();
        // A descendant endpoint also establishes an empty nonterminal's
        // existence. Authenticate that evidence along with both intervals.
        if has_unsafe_ancestor(qname, &usable) {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        }
        let closest = (0..=qlabels.len() - zone_labels).find_map(|dropped| {
            let candidate = DomainName::from_labels(qlabels[dropped..].to_vec()).ok()?;
            usable
                .iter()
                .find(|(_, record, nsec)| {
                    record.name.is_descendant_of(&candidate)
                        || nsec.next_domain_name.is_descendant_of(&candidate)
                })
                .map(|&(index, _, _)| (candidate, index))
        });
        let Some((closest_encloser, closest_index)) = closest else {
            return DnssecValidation::Bogus(DnssecValidationError::MissingDenialProof);
        };
        let Ok(wildcard) = wildcard_name(&closest_encloser) else {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        };
        let Some(next_closer) = next_closer_name(qname, &closest_encloser) else {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        };
        let qname_cover = usable
            .iter()
            .find(|(_, record, nsec)| nsec.covers_name(&record.name, &next_closer))
            .map(|&(index, _, _)| index);
        let wildcard_cover = usable
            .iter()
            .find(|(_, record, nsec)| nsec.covers_name(&record.name, &wildcard))
            .map(|&(index, _, _)| index);
        let (Some(qname_cover), Some(wildcard_cover)) = (qname_cover, wildcard_cover) else {
            return DnssecValidation::Bogus(DnssecValidationError::MissingDenialProof);
        };
        let indices = [closest_index, qname_cover, wildcard_cover]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        match self.authenticate_denial_records(&indices, nsec_records, signatures, now) {
            Ok((ttl, signature_expiration)) => DnssecValidation::Secure(AuthenticatedDenial {
                authenticated_ttl: ttl,
                signature_expiration,
                opt_out: false,
                kind: DnssecDenialKind::NameError,
                proof_record_indices: indices,
            }),
            Err(error) => DnssecValidation::Bogus(error),
        }
    }

    pub(super) fn validate_nsec_empty_nodata(
        &self,
        qname: &DomainName,
        records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
    ) -> Option<DnssecValidation<AuthenticatedDenial>> {
        if !qname.is_descendant_of(&self.zone) {
            return Some(DnssecValidation::Bogus(
                DnssecValidationError::InvalidDenialProof,
            ));
        }
        let usable = records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| match &record.rdata {
                RData::NSEC(nsec)
                    if record.rtype == RecordType::NSEC
                        && record.class == self.class
                        && record.name.is_descendant_of(&self.zone)
                        && nsec.next_domain_name.is_descendant_of(&self.zone) =>
                {
                    Some((index, record, nsec))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if has_unsafe_ancestor(qname, &usable) {
            return Some(DnssecValidation::Bogus(
                DnssecValidationError::InvalidDenialProof,
            ));
        }
        let (index, _, _) = usable.into_iter().find(|(_, record, nsec)| {
            nsec.next_domain_name.is_descendant_of(qname)
                && !nsec.next_domain_name.eq_dns(qname)
                && nsec.covers_name(&record.name, qname)
        })?;
        Some(
            match self.authenticate_denial_records(&[index], records, signatures, now) {
                Ok((ttl, signature_expiration)) => DnssecValidation::Secure(AuthenticatedDenial {
                    authenticated_ttl: ttl,
                    signature_expiration,
                    opt_out: false,
                    kind: DnssecDenialKind::NoData,
                    proof_record_indices: vec![index],
                }),
                Err(error) => DnssecValidation::Bogus(error),
            },
        )
    }
}

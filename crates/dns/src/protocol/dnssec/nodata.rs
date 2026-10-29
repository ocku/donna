use super::authentication::{
    denial_kind, next_closer_name, unsafe_closest_encloser_bitmap, unsafe_denial_bitmap,
    wildcard_name,
};
use super::*;

impl AuthenticatedDnskeySet {
    fn validate_nsec_wildcard_nodata(
        &self,
        qname: &DomainName,
        qtype: u16,
        records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
    ) -> DnssecValidation<AuthenticatedDenial> {
        // The literal wildcard proves its parent exists. Denying the next
        // closer name establishes that this parent is the closest encloser;
        // denying QNAME alone would allow replay below an existing subtree.
        for (index, record) in records.iter().enumerate() {
            let RData::NSEC(nsec) = &record.rdata else {
                continue;
            };
            if record.rtype != RecordType::NSEC
                || record.class != self.class
                || record
                    .name
                    .as_ref()
                    .first()
                    .is_none_or(|label| label != b"*")
                || !record.name.is_descendant_of(&self.zone)
                || !nsec.next_domain_name.is_descendant_of(&self.zone)
                || !nsec.proves_nodata(qtype)
                || unsafe_closest_encloser_bitmap(nsec.type_bitmap.codes())
            {
                continue;
            }
            let closest = DomainName::from_labels(record.name.as_ref()[1..].to_vec()).unwrap();
            let Some(next_closer) = next_closer_name(qname, &closest) else {
                continue;
            };
            let covering = records.iter().enumerate().find_map(|(index, record)| {
                let RData::NSEC(nsec) = &record.rdata else {
                    return None;
                };
                (record.rtype == RecordType::NSEC
                    && record.class == self.class
                    && record.name.is_descendant_of(&self.zone)
                    && nsec.next_domain_name.is_descendant_of(&self.zone)
                    && nsec.covers_name(&record.name, &next_closer))
                .then_some(index)
            });
            if let Some(covering) = covering {
                return self.authenticate_nodata(&[index, covering], records, signatures, now);
            }
        }
        DnssecValidation::Bogus(DnssecValidationError::MissingDenialProof)
    }

    fn validate_nsec3_wildcard_nodata(
        &self,
        qname: &DomainName,
        qtype: u16,
        records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
        maximum_iterations: u16,
    ) -> DnssecValidation<AuthenticatedDenial> {
        let proof = match find_nsec3_closest_encloser(
            records,
            &self.zone,
            self.class,
            qname,
            maximum_iterations,
        ) {
            Ok(proof) => proof,
            Err(error) => return DnssecValidation::Bogus(DnssecValidationError::Nsec3Proof(error)),
        };
        let opt_out =
            matches!(&records[proof.covering_record].rdata, RData::NSEC3(nsec3) if nsec3.opt_out());
        let Ok(wildcard) = wildcard_name(&proof.closest_encloser) else {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        };
        for (index, record) in records.iter().enumerate() {
            let RData::NSEC3(nsec3) = &record.rdata else {
                continue;
            };
            if record.rtype != RecordType::NSEC3
                || record.class != self.class
                || nsec3.hash_algorithm != 1
                || nsec3.flags & !crate::Nsec3::OPT_OUT_FLAG != 0
                || !nsec3
                    .matches_name(&record.name, &self.zone, &wildcard, maximum_iterations)
                    .unwrap_or(false)
                || nsec3.type_bitmap.as_ref().is_some_and(|bitmap| {
                    let codes = bitmap.codes();
                    codes.contains(&qtype)
                        || codes.contains(&u16::from(RecordType::CNAME))
                        || unsafe_closest_encloser_bitmap(codes)
                })
            {
                continue;
            }
            let mut result = self.authenticate_nodata(
                &[proof.matching_record, proof.covering_record, index],
                records,
                signatures,
                now,
            );
            if let DnssecValidation::Secure(denial) = &mut result {
                denial.opt_out = opt_out;
            }
            return result;
        }
        DnssecValidation::Bogus(DnssecValidationError::MissingDenialProof)
    }

    fn authenticate_nodata(
        &self,
        indices: &[usize],
        records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
    ) -> DnssecValidation<AuthenticatedDenial> {
        let indices = indices
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        match self.authenticate_denial_records(&indices, records, signatures, now) {
            Ok((ttl, signature_expiration)) => DnssecValidation::Secure(AuthenticatedDenial {
                authenticated_ttl: ttl,
                signature_expiration,
                opt_out: false,
                kind: DnssecDenialKind::NoData,
                proof_record_indices: indices,
            }),
            Err(error) => DnssecValidation::Bogus(error),
        }
    }
    /// Validates RFC 4035 NSEC denial of `qtype` at `qname`, including
    /// wildcard NODATA with denial of a closer matching name.
    pub fn validate_nsec_nodata(
        &self,
        qname: &DomainName,
        qtype: u16,
        nsec_records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
    ) -> DnssecValidation<AuthenticatedDenial> {
        if !qname.is_descendant_of(&self.zone) {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        }
        let Some((index, record, nsec)) = nsec_records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| match &record.rdata {
                RData::NSEC(nsec)
                    if record.rtype == RecordType::NSEC
                        && record.class == self.class
                        && record.name.eq_dns(qname) =>
                {
                    Some((index, record, nsec))
                }
                _ => None,
            })
            .find(|(_, _, nsec)| nsec.proves_nodata(qtype))
        else {
            if let Some(result) =
                self.validate_nsec_empty_nodata(qname, nsec_records, signatures, now)
            {
                return result;
            }
            return self.validate_nsec_wildcard_nodata(qname, qtype, nsec_records, signatures, now);
        };
        if !record.name.is_descendant_of(&self.zone)
            || !nsec.next_domain_name.is_descendant_of(&self.zone)
            || unsafe_denial_bitmap(nsec.type_bitmap.codes(), qtype)
        {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        }
        match self.authenticate_denial_records(&[index], nsec_records, signatures, now) {
            Ok((ttl, signature_expiration)) => DnssecValidation::Secure(AuthenticatedDenial {
                authenticated_ttl: ttl,
                signature_expiration,
                opt_out: false,
                kind: denial_kind(qtype, nsec.type_bitmap.codes()),
                proof_record_indices: vec![index],
            }),
            Err(error) => DnssecValidation::Bogus(error),
        }
    }

    /// Validates RFC 5155 NSEC3 denial of `qtype` at `qname`, including
    /// wildcard NODATA with a closest-encloser proof.
    pub fn validate_nsec3_nodata(
        &self,
        qname: &DomainName,
        qtype: u16,
        nsec3_records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
        maximum_iterations: u16,
    ) -> DnssecValidation<AuthenticatedDenial> {
        for (index, record) in nsec3_records.iter().enumerate() {
            let RData::NSEC3(nsec3) = &record.rdata else {
                continue;
            };
            if record.rtype != RecordType::NSEC3
                || record.class != self.class
                || nsec3.hash_algorithm != 1
                || nsec3.flags & !crate::Nsec3::OPT_OUT_FLAG != 0
            {
                continue;
            }
            let matches =
                match nsec3.matches_name(&record.name, &self.zone, qname, maximum_iterations) {
                    Ok(matches) => matches,
                    Err(error) => {
                        return DnssecValidation::Bogus(DnssecValidationError::Nsec3Proof(
                            Nsec3ClosestEncloserError::MalformedRecord(error),
                        ));
                    }
                };
            if !matches {
                continue;
            }
            let codes = nsec3.type_bitmap.as_ref().map(|bitmap| bitmap.codes());
            let proves_nodata = codes.is_none_or(|codes| {
                !codes.contains(&qtype)
                    && !codes.contains(&u16::from(RecordType::CNAME))
                    && !unsafe_denial_bitmap(codes, qtype)
            });
            if !proves_nodata {
                return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
            }
            return match self.authenticate_denial_records(&[index], nsec3_records, signatures, now)
            {
                Ok((ttl, signature_expiration)) => DnssecValidation::Secure(AuthenticatedDenial {
                    authenticated_ttl: ttl,
                    signature_expiration,
                    opt_out: false,
                    kind: DnssecDenialKind::NoData,
                    proof_record_indices: vec![index],
                }),
                Err(error) => DnssecValidation::Bogus(error),
            };
        }
        self.validate_nsec3_wildcard_nodata(
            qname,
            qtype,
            nsec3_records,
            signatures,
            now,
            maximum_iterations,
        )
    }
}

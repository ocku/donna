use crate::protocol::mac::Sha256Mac;
use hmac::Mac;

use super::authentication::{next_closer_name, validate_rrset_with_keys, wildcard_name};
use super::*;
use crate::{Headers, Message, QClassType, QueryType, Question};

/// An apex DNSKEY RRset authenticated from a trust anchor or parent DS RRset.
#[derive(Debug, Clone)]
pub struct AuthenticatedDnskeySet {
    pub(super) zone: DomainName,
    pub(super) class: ClassType,
    pub(super) records: std::sync::Arc<[ResourceRecord]>,
    pub(super) authenticated_ttl: u32,
    pub(super) signature_expiration: u32,
    // Shared by immutable clones; mathematical success only. Per-call key,
    // time, canonical data, candidate ordering and TTL checks still execute.
    pub(super) soa_signature: std::sync::Arc<crate::protocol::SuccessfulSignatureCache>,
    // A scoped clone can retain up to eight denial RRset math results. The
    // owner cache controls lifetime; every ordinary verification check remains.
    pub(super) denial_signatures:
        Option<std::sync::Arc<super::denial_signature_cache::DenialSignatureCache>>,
    // Separate single-entry memo for recurring signed DNAME RRsets. It holds
    // only mathematical success, never trust, time, or cached TTL decisions.
    pub(super) dname_signature:
        std::sync::OnceLock<std::sync::Arc<crate::protocol::SuccessfulSignatureCache>>,
}

impl AuthenticatedDnskeySet {
    /// Exports authenticated chain material for an application-owned cache.
    ///
    /// The secret must be unavailable to the storage service; `binding` must
    /// identify the application's trust-anchor and validation policy. This
    /// authenticates provenance, not freshness: the caller must separately
    /// retain and enforce the complete chain's absolute deadline. Mathematical
    /// verification memoization is deliberately excluded.
    pub fn export_cache_material(
        &self,
        secret: &[u8; 32],
        binding: &[u8],
    ) -> Result<Vec<u8>, crate::wire::WireError> {
        use crate::IntoWire;
        let message = Message {
            headers: Headers {
                qr: true,
                ..Headers::default()
            },
            questions: vec![Question {
                qname: self.zone.clone(),
                qtype: QueryType::DNSKEY,
                qclass: QClassType::Class(self.class),
            }],
            answers: self.records.to_vec(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let wire = message.into_wire()?;
        let mut bytes = b"DNKEY001".to_vec();
        bytes.extend_from_slice(&self.authenticated_ttl.to_be_bytes());
        bytes.extend_from_slice(&self.signature_expiration.to_be_bytes());
        bytes.extend_from_slice(&wire);
        let mut context = Sha256Mac::new_from_slice(secret).expect("HMAC accepts any key length");
        context.update(b"donna authenticated DNSKEY cache v1\0");
        context.update(&(binding.len() as u64).to_be_bytes());
        context.update(binding);
        context.update(&bytes);
        bytes.extend_from_slice(&context.finalize().into_bytes());
        Ok(bytes)
    }

    /// Restores only authenticated, well-formed, unexpired cache material.
    ///
    /// This accepts at most one maximum-sized DNS message plus fixed metadata.
    /// A wrong secret, policy binding, malformed encoding or expired DNSSEC
    /// serial deadline returns `None`. The caller must still enforce the full
    /// chain's original TTL and monotonic/wall-clock lifetime bounds.
    pub fn import_cache_material(
        bytes: &[u8],
        secret: &[u8; 32],
        binding: &[u8],
        now: u32,
    ) -> Option<Self> {
        use crate::FromWire;
        if !(60..=65_583).contains(&bytes.len()) || bytes.get(..8)? != b"DNKEY001" {
            return None;
        }
        let (payload, tag) = bytes.split_at(bytes.len() - 32);
        let mut context = Sha256Mac::new_from_slice(secret).expect("HMAC accepts any key length");
        context.update(b"donna authenticated DNSKEY cache v1\0");
        context.update(&(binding.len() as u64).to_be_bytes());
        context.update(binding);
        context.update(payload);
        context.verify_slice(tag).ok()?;
        let authenticated_ttl = u32::from_be_bytes(payload.get(8..12)?.try_into().ok()?);
        let signature_expiration = u32::from_be_bytes(payload.get(12..16)?.try_into().ok()?);
        let remaining = signature_expiration.wrapping_sub(now);
        if remaining == 0 || remaining >= (1 << 31) || authenticated_ttl == 0 {
            return None;
        }
        let message = Message::from_wire(payload.get(16..)?).ok()?;
        let [question] = message.questions.as_slice() else {
            return None;
        };
        let QClassType::Class(class) = question.qclass else {
            return None;
        };
        if question.qtype != QueryType::DNSKEY
            || message.answers.is_empty()
            || !message.authorities.is_empty()
            || !message.additionals.is_empty()
            || message.answers.iter().any(|record| {
                record.rtype != RecordType::DNSKEY
                    || record.class != class
                    || !record.name.eq_dns(&question.qname)
            })
        {
            return None;
        }
        Some(Self {
            zone: question.qname.clone(),
            class,
            records: message.answers.into(),
            authenticated_ttl,
            signature_expiration,
            soa_signature: Default::default(),
            dname_signature: Default::default(),
            denial_signatures: None,
        })
    }

    /// Returns the DNSSEC serial expiration of the authenticating DNSKEY signature.
    /// This does not include parent DS lifetimes; callers must bound the full chain.
    pub const fn signature_expiration(&self) -> u32 {
        self.signature_expiration
    }

    /// Returns the authenticated zone apex.
    pub const fn zone(&self) -> &DomainName {
        &self.zone
    }

    /// Returns the DNS class of the authenticated zone.
    pub const fn class(&self) -> ClassType {
        self.class
    }

    /// Returns the authenticated DNSKEY records.
    pub fn records(&self) -> &[ResourceRecord] {
        &self.records
    }

    /// Returns the RFC 4035 upper bound on the authenticated cache lifetime.
    pub const fn authenticated_ttl(&self) -> u32 {
        self.authenticated_ttl
    }

    /// Validates an RRset using any authenticated zone key that successfully
    /// verifies an applicable RRSIG.
    pub fn validate_rrset(
        &self,
        records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
    ) -> DnssecValidation<AuthenticatedRrset> {
        let denial_cache = self
            .denial_signatures
            .as_ref()
            .and_then(|cache| cache.for_rrset(records));
        validate_rrset_with_keys(
            records,
            signatures,
            &self.zone,
            &self.records,
            now,
            match records {
                [record] if record.rtype == RecordType::SOA => Some(self.soa_signature.as_ref()),
                [record] if record.rtype == RecordType::DNAME => {
                    Some(self.dname_signature.get_or_init(Default::default).as_ref())
                }
                _ => denial_cache.as_deref(),
            },
        )
    }

    /// Validates the NSEC denial required for a wildcard-expanded positive
    /// answer whose RRSIG identified `closest_encloser`.
    pub fn validate_nsec_wildcard_expansion(
        &self,
        qname: &DomainName,
        closest_encloser: &DomainName,
        nsec_records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
    ) -> DnssecValidation<AuthenticatedDenial> {
        let Some(next_closer) = next_closer_name(qname, closest_encloser) else {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        };
        if !closest_encloser.is_descendant_of(&self.zone) {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        }
        let covering = nsec_records.iter().enumerate().find_map(|(index, record)| {
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
        let Some(index) = covering else {
            return DnssecValidation::Bogus(DnssecValidationError::MissingDenialProof);
        };
        match self.authenticate_denial_records(&[index], nsec_records, signatures, now) {
            Ok((ttl, signature_expiration)) => DnssecValidation::Secure(AuthenticatedDenial {
                authenticated_ttl: ttl,
                signature_expiration,
                opt_out: false,
                kind: DnssecDenialKind::WildcardExpansion,
                proof_record_indices: vec![index],
            }),
            Err(error) => DnssecValidation::Bogus(error),
        }
    }

    /// Validates RFC 5155 proof that a delegation has no DS RRset.
    ///
    /// A matching NSEC3 may directly omit DS and CNAME. Otherwise, a closest
    /// encloser proof is required and its next-closer covering record must set
    /// the Opt-Out flag.
    pub fn validate_nsec3_insecure_delegation(
        &self,
        delegation: &DomainName,
        nsec3_records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
        maximum_iterations: u16,
    ) -> DnssecValidation<AuthenticatedDenial> {
        let direct = self.validate_nsec3_nodata(
            delegation,
            u16::from(RecordType::DS),
            nsec3_records,
            signatures,
            now,
            maximum_iterations,
        );
        let matching_exists = nsec3_records.iter().any(|record| {
            let RData::NSEC3(nsec3) = &record.rdata else {
                return false;
            };
            record.rtype == RecordType::NSEC3
                && record.class == self.class
                && nsec3.hash_algorithm == 1
                && nsec3.flags & !crate::Nsec3::OPT_OUT_FLAG == 0
                && nsec3
                    .matches_name(&record.name, &self.zone, delegation, maximum_iterations)
                    .unwrap_or(false)
        });
        if matching_exists {
            return match direct {
                DnssecValidation::Secure(mut proof) => {
                    let valid_delegation = proof.proof_record_indices.iter().all(|&index| {
                        matches!(&nsec3_records[index].rdata, RData::NSEC3(nsec3)
                        if nsec3.type_bitmap.as_ref().is_some_and(|bitmap| {
                            bitmap.codes().contains(&u16::from(RecordType::NS))
                                && !bitmap.codes().contains(&u16::from(RecordType::SOA))
                        }))
                    });
                    if !valid_delegation {
                        return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
                    }
                    proof.kind = DnssecDenialKind::UnsignedDelegation;
                    DnssecValidation::Secure(proof)
                }
                DnssecValidation::Insecure => DnssecValidation::Insecure,
                DnssecValidation::Bogus(error) => DnssecValidation::Bogus(error),
                DnssecValidation::Indeterminate(error) => DnssecValidation::Indeterminate(error),
            };
        }

        let proof = match find_nsec3_closest_encloser(
            nsec3_records,
            &self.zone,
            self.class,
            delegation,
            maximum_iterations,
        ) {
            Ok(proof) => proof,
            Err(error) => {
                return DnssecValidation::Bogus(DnssecValidationError::Nsec3Proof(error));
            }
        };
        let Some(covering) = nsec3_records.get(proof.covering_record) else {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        };
        if !matches!(&covering.rdata, RData::NSEC3(nsec3) if nsec3.opt_out()) {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        }
        let indices = [proof.matching_record, proof.covering_record]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        match self.authenticate_denial_records(&indices, nsec3_records, signatures, now) {
            Ok((ttl, signature_expiration)) => DnssecValidation::Secure(AuthenticatedDenial {
                authenticated_ttl: ttl,
                signature_expiration,
                opt_out: true,
                kind: DnssecDenialKind::UnsignedDelegation,
                proof_record_indices: indices,
            }),
            Err(error) => DnssecValidation::Bogus(error),
        }
    }

    /// Validates an RFC 5155 NSEC3 name-error proof, including the closest
    /// encloser, next-closer denial, and wildcard denial.
    pub fn validate_nsec3_name_error(
        &self,
        qname: &DomainName,
        nsec3_records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
        maximum_iterations: u16,
    ) -> DnssecValidation<AuthenticatedDenial> {
        let proof = match find_nsec3_closest_encloser(
            nsec3_records,
            &self.zone,
            self.class,
            qname,
            maximum_iterations,
        ) {
            Ok(proof) => proof,
            Err(error) => {
                return DnssecValidation::Bogus(DnssecValidationError::Nsec3Proof(error));
            }
        };
        let Ok(wildcard) = wildcard_name(&proof.closest_encloser) else {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        };
        let wildcard_record = nsec3_records
            .iter()
            .enumerate()
            .find_map(|(index, record)| {
                let RData::NSEC3(nsec3) = &record.rdata else {
                    return None;
                };
                (record.rtype == RecordType::NSEC3
                    && record.class == self.class
                    && nsec3.hash_algorithm == 1
                    && nsec3.flags & !crate::Nsec3::OPT_OUT_FLAG == 0
                    && nsec3
                        .covers_name(&record.name, &self.zone, &wildcard, maximum_iterations)
                        .unwrap_or(false))
                .then_some(index)
            });
        let Some(wildcard_record) = wildcard_record else {
            return DnssecValidation::Bogus(DnssecValidationError::MissingDenialProof);
        };
        let indices = [
            proof.matching_record,
            proof.covering_record,
            wildcard_record,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
        match self.authenticate_denial_records(&indices, nsec3_records, signatures, now) {
            Ok((ttl, signature_expiration)) => DnssecValidation::Secure(AuthenticatedDenial {
                authenticated_ttl: ttl,
                signature_expiration,
                opt_out: matches!(&nsec3_records[proof.covering_record].rdata, RData::NSEC3(nsec3) if nsec3.opt_out()),
                kind: DnssecDenialKind::NameError,
                proof_record_indices: indices,
            }),
            Err(error) => DnssecValidation::Bogus(error),
        }
    }

    /// Validates the NSEC3 next-closer denial required for a
    /// wildcard-expanded positive answer whose RRSIG identified
    /// `closest_encloser`.
    pub fn validate_nsec3_wildcard_expansion(
        &self,
        qname: &DomainName,
        closest_encloser: &DomainName,
        nsec3_records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
        maximum_iterations: u16,
    ) -> DnssecValidation<AuthenticatedDenial> {
        let Some(next_closer) = next_closer_name(qname, closest_encloser) else {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        };
        if !closest_encloser.is_descendant_of(&self.zone) {
            return DnssecValidation::Bogus(DnssecValidationError::InvalidDenialProof);
        }
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
            match nsec3.covers_name(&record.name, &self.zone, &next_closer, maximum_iterations) {
                Ok(true) => {
                    return match self.authenticate_denial_records(
                        &[index],
                        nsec3_records,
                        signatures,
                        now,
                    ) {
                        Ok((ttl, signature_expiration)) => {
                            DnssecValidation::Secure(AuthenticatedDenial {
                                authenticated_ttl: ttl,
                                signature_expiration,
                                opt_out: nsec3.opt_out(),
                                kind: DnssecDenialKind::WildcardExpansion,
                                proof_record_indices: vec![index],
                            })
                        }
                        Err(error) => DnssecValidation::Bogus(error),
                    };
                }
                Ok(false) => {}
                Err(error) => {
                    return DnssecValidation::Bogus(DnssecValidationError::Nsec3Proof(
                        Nsec3ClosestEncloserError::MalformedRecord(error),
                    ));
                }
            }
        }
        DnssecValidation::Bogus(DnssecValidationError::MissingDenialProof)
    }

    pub(super) fn authenticate_denial_records(
        &self,
        indices: &[usize],
        records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        now: u32,
    ) -> Result<(u32, u32), DnssecValidationError> {
        let mut ttl = u32::MAX;
        let mut signature_ttl = u32::MAX;
        if indices.is_empty() {
            return Err(DnssecValidationError::MissingDenialProof);
        }
        for &index in indices {
            let Some(proof_record) = records.get(index) else {
                return Err(DnssecValidationError::InvalidDenialProof);
            };
            let rrset = records
                .iter()
                .filter(|record| {
                    record.name.eq_dns(&proof_record.name)
                        && record.rtype == proof_record.rtype
                        && record.class == proof_record.class
                })
                .cloned()
                .collect::<Vec<_>>();
            // Denial owners in the authority section are literal. Require
            // the exact label count before trying signatures so an expanded
            // candidate cannot replay a higher wildcard or mask a valid one.
            let labels = proof_record.name.as_ref();
            let expected_labels =
                labels.len() - usize::from(labels.first().is_some_and(|label| label == b"*"));
            let literal_signatures = signatures.iter().filter(|record| {
                matches!(&record.rdata, RData::RRSIG(signature) if usize::from(signature.labels) == expected_labels)
            }).cloned().collect::<Vec<_>>();
            match self.validate_rrset(&rrset, &literal_signatures, now) {
                DnssecValidation::Secure(authenticated) => {
                    ttl = ttl.min(authenticated.authenticated_ttl());
                    signature_ttl =
                        signature_ttl.min(authenticated.signature_expiration().wrapping_sub(now));
                }
                DnssecValidation::Bogus(error) | DnssecValidation::Indeterminate(error) => {
                    return Err(error);
                }
                DnssecValidation::Insecure => {
                    return Err(DnssecValidationError::NoValidSignature);
                }
            }
        }
        Ok((ttl, now.wrapping_add(signature_ttl)))
    }
}

#[cfg(test)]
mod tests;

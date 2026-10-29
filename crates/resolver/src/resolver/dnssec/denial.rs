use dns::{
    AuthenticatedDenial, AuthenticatedDnskeySet, DnssecDenialKind, DnssecValidationError,
    DomainName, Message, RecordType,
};
use transport::Transport;

use crate::ResolveError;

use super::{super::Resolver, records::validation_result};

impl<T: Transport> Resolver<T> {
    pub(super) fn validate_unsigned_delegation(
        &self,
        keys: &AuthenticatedDnskeySet,
        child: &DomainName,
        response: &Message,
        now: u32,
    ) -> Result<AuthenticatedDenial, ResolveError> {
        let signatures = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::RRSIG && record.class == keys.class());
        let signatures = signatures.cloned().collect::<Vec<_>>();
        let nsec3 = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .cloned()
            .collect::<Vec<_>>();
        let validation = if nsec3.is_empty() {
            let nsec = response
                .authorities
                .iter()
                .filter(|record| record.rtype == RecordType::NSEC)
                .cloned()
                .collect::<Vec<_>>();
            keys.validate_nsec_nodata(child, u16::from(RecordType::DS), &nsec, &signatures, now)
        } else {
            keys.validate_nsec3_insecure_delegation(
                child,
                &nsec3,
                &signatures,
                now,
                self.config.max_nsec3_iterations,
            )
        };
        let denial = validation_result(validation)?;
        if denial.kind() != DnssecDenialKind::UnsignedDelegation {
            return Err(ResolveError::DnssecBogus(
                DnssecValidationError::MissingDenialProof,
            ));
        }
        Ok(denial)
    }

    pub(super) fn validate_negative_denial(
        &self,
        keys: &AuthenticatedDnskeySet,
        qname: &DomainName,
        qtype: u16,
        response: &Message,
        now: u32,
    ) -> Result<AuthenticatedDenial, ResolveError> {
        let signatures = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::RRSIG)
            .cloned()
            .collect::<Vec<_>>();
        let nsec3 = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .cloned()
            .collect::<Vec<_>>();
        let validation = if nsec3.is_empty() {
            let nsec = response
                .authorities
                .iter()
                .filter(|record| record.rtype == RecordType::NSEC)
                .cloned()
                .collect::<Vec<_>>();
            if response.headers.rcode == dns::RCode::NameError {
                keys.validate_nsec_name_error(qname, &nsec, &signatures, now)
            } else {
                keys.validate_nsec_nodata(qname, qtype, &nsec, &signatures, now)
            }
        } else if response.headers.rcode == dns::RCode::NameError {
            keys.validate_nsec3_name_error(
                qname,
                &nsec3,
                &signatures,
                now,
                self.config.max_nsec3_iterations,
            )
        } else {
            keys.validate_nsec3_nodata(
                qname,
                qtype,
                &nsec3,
                &signatures,
                now,
                self.config.max_nsec3_iterations,
            )
        };
        validation_result(validation)
    }

    pub(super) fn validate_wildcard_denial(
        &self,
        keys: &AuthenticatedDnskeySet,
        qname: &DomainName,
        closest_encloser: &DomainName,
        response: &Message,
        now: u32,
    ) -> Result<AuthenticatedDenial, ResolveError> {
        let signatures = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::RRSIG)
            .cloned()
            .collect::<Vec<_>>();
        let nsec3 = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .cloned()
            .collect::<Vec<_>>();
        let validation = if nsec3.is_empty() {
            let nsec = response
                .authorities
                .iter()
                .filter(|record| record.rtype == RecordType::NSEC)
                .cloned()
                .collect::<Vec<_>>();
            keys.validate_nsec_wildcard_expansion(qname, closest_encloser, &nsec, &signatures, now)
        } else {
            keys.validate_nsec3_wildcard_expansion(
                qname,
                closest_encloser,
                &nsec3,
                &signatures,
                now,
                self.config.max_nsec3_iterations,
            )
        };
        validation_result(validation)
    }
}

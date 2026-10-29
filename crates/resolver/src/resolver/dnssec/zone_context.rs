//! Namespace and signature-time guards shared with cache eligibility checks.
use super::{
    Resolver,
    key_cache::{ValidationTime, ZoneKey},
};
use crate::ResolveError;
use dns::{ClassType, DnssecValidationError, DomainName, RData, RecordType};
use transport::Transport;

pub(super) fn check_signature_time(
    time: ValidationTime,
    signature_ttl: u32,
) -> Result<(), ResolveError> {
    let wall_age = super::records::unix_time().wrapping_sub(time.unix);
    if wall_age > signature_ttl || time.instant.elapsed().as_secs() > u64::from(signature_ttl) {
        return Err(ResolveError::DnssecBogus(DnssecValidationError::Signature(
            dns::RrsigVerificationError::BadTime,
        )));
    }
    Ok(())
}

impl<T: Transport> Resolver<T> {
    /// Unauthenticated signer and SOA names cannot move an answer outside its
    /// namespace or bypass a more specific configured trust anchor.
    pub(super) fn check_answer_zone(
        &self,
        owner: &DomainName,
        zone: &DomainName,
        class: ClassType,
        parent_side_ds: bool,
    ) -> Result<(), ResolveError> {
        if !owner.is_descendant_of(zone)
            || (parent_side_ds && owner.eq_dns(zone) && !owner.as_ref().is_empty())
            || self.config.trust_anchors.iter().any(|record| {
                record.class == class
                    && record.rtype == RecordType::DNSKEY
                    && matches!(record.rdata, RData::DNSKEY(_))
                    && owner.is_descendant_of(&record.name)
                    // DS belongs to the parent namespace, even when the
                    // child apex has its own configured trust anchor.
                    && !(parent_side_ds && owner.eq_dns(&record.name))
                    && !zone.is_descendant_of(&record.name)
            })
        {
            return Err(ResolveError::DnssecBogus(
                DnssecValidationError::InvalidRrset,
            ));
        }
        Ok(())
    }

    pub(super) fn zone_cache_key(
        &self,
        zone: &DomainName,
        class: ClassType,
    ) -> Result<ZoneKey, ResolveError> {
        let anchor = self
            .config
            .trust_anchors
            .iter()
            .filter(|record| {
                record.class == class
                    && record.rtype == RecordType::DNSKEY
                    && zone.is_descendant_of(&record.name)
                    && matches!(record.rdata, RData::DNSKEY(_))
            })
            .max_by_key(|record| record.name.as_ref().len())
            .map(|record| record.name.clone())
            .ok_or(ResolveError::DnssecIndeterminate(
                DnssecValidationError::MissingTrustAnchor,
            ))?;
        Ok(ZoneKey {
            zone: zone.clone(),
            class,
            anchor,
        })
    }
}

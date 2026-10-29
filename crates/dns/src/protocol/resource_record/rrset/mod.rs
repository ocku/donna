use std::collections::HashMap;

use super::{ClassType, RData, RecordType, ResourceRecord};
use crate::DomainName;
use crate::constants::MAX_TTL;

mod error;
mod validation;

pub use error::RecordValidationError;
use validation::rdata_matches_type;
pub(super) use validation::same_rdata;
pub(crate) use validation::{
    validate_rdata_forwarded, validate_rdata_wire, validate_received_edns_options,
};

/// A complete DNS resource-record set.
///
/// Every member has the same owner, class, type, and TTL. Identical records
/// are rejected rather than retained.
#[derive(Debug, Clone)]
pub(crate) struct RrSet {
    pub(crate) name: DomainName,
    pub(crate) rtype: RecordType,
    pub(crate) class: ClassType,
    pub(crate) ttl: u32,
    pub(crate) records: Vec<ResourceRecord>,
}

impl RrSet {
    /// Builds and validates a complete RRSet from its records.
    pub(crate) fn try_from_records(
        records: Vec<ResourceRecord>,
    ) -> Result<Self, RecordValidationError> {
        let first = records.first().ok_or(RecordValidationError::EmptyRrSet)?;
        let set = Self {
            name: first.name.clone(),
            rtype: first.rtype,
            class: first.class,
            ttl: first.ttl,
            records,
        };
        set.validate()?;
        Ok(set)
    }

    /// Validates the RRSet invariants required for outgoing DNS data.
    pub(crate) fn validate(&self) -> Result<(), RecordValidationError> {
        if self.records.is_empty() {
            return Err(RecordValidationError::EmptyRrSet);
        }
        if is_rrsig_type(self.rtype) && self.records.len() > 1 {
            return Err(RecordValidationError::MixedRrSet);
        }
        for (index, record) in self.records.iter().enumerate() {
            record.validate()?;
            if !same_rrset_key(record, &self.name, self.rtype, self.class) {
                return Err(RecordValidationError::MixedRrSet);
            }
            if record.ttl != self.ttl {
                return Err(RecordValidationError::InconsistentTtl {
                    expected: self.ttl,
                    actual: record.ttl,
                });
            }
            if self.records[..index]
                .iter()
                .any(|previous| same_record(previous, record))
            {
                return Err(RecordValidationError::DuplicateRecord);
            }
        }
        Ok(())
    }
}

impl ResourceRecord {
    /// Validates all record properties required for RFC 1035 wire encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if the TTL, TYPE, CLASS, RDATA kind, or RDATA length
    /// cannot be encoded canonically.
    pub fn validate(&self) -> Result<(), RecordValidationError> {
        self.validate_with_owner(&self.name)
    }

    /// Validates the same immutable RDATA under an explicitly selected owner.
    /// Used by checked wildcard writers; no record fields are skipped.
    pub(crate) fn validate_with_owner(
        &self,
        owner: &DomainName,
    ) -> Result<(), RecordValidationError> {
        if self.rtype == RecordType::OPT {
            if *owner != DomainName::root()
                || !matches!(self.class, ClassType::Unknown(_))
                || !matches!(self.rdata, RData::OPT(_))
            {
                return Err(RecordValidationError::InvalidRDataType);
            }
            let z = (self.ttl & 0x7fff) as u16;
            if z != 0 {
                return Err(RecordValidationError::NonzeroEdnsZ { value: z });
            }
            return validate_rdata_wire(&self.rdata);
        }
        if self.rtype == RecordType::TSIG {
            if self.class != ClassType::Unknown(255)
                || self.ttl != 0
                || !matches!(self.rdata, RData::TSIG(_))
            {
                return Err(RecordValidationError::InvalidRDataType);
            }
            return validate_rdata_wire(&self.rdata);
        }
        if matches!(&self.rdata, RData::SIG(sig) if sig.is_sig0()) {
            if self.rtype != RecordType::SIG {
                return Err(RecordValidationError::InvalidRDataType);
            }
            return validate_rdata_wire(&self.rdata);
        }
        if self.ttl > MAX_TTL {
            return Err(RecordValidationError::TtlTooLarge { value: self.ttl });
        }
        if let RecordType::Unknown(value) = self.rtype
            && (matches!(value, 0 | u16::MAX)
                || RecordType::is_known_code(value)
                || RecordType::is_query_only_code(value)
                || RecordType::is_unassigned_query_or_meta_code(value))
        {
            return Err(RecordValidationError::NonCanonicalRecordType { value });
        }
        if let ClassType::Unknown(value) = self.class
            && (!ClassType::is_data_code(value) || matches!(value, 1 | 3 | 4))
        {
            return Err(RecordValidationError::NonCanonicalClass { value });
        }
        if !rdata_matches_type(self.rtype, self.class, &self.rdata) {
            return Err(RecordValidationError::InvalidRDataType);
        }
        if let RData::RRSIG(rrsig) = &self.rdata {
            let owner_labels = owner.as_ref().len();
            if usize::from(rrsig.labels) > owner_labels {
                return Err(RecordValidationError::RrsigLabelsTooLarge {
                    labels: rrsig.labels,
                    owner_labels,
                });
            }
            if matches!(rrsig.type_covered, 0 | 41 | 46 | 128..=255 | u16::MAX) {
                return Err(RecordValidationError::InvalidRrsigTypeCovered {
                    value: rrsig.type_covered,
                });
            }
            if rrsig.original_ttl > MAX_TTL {
                return Err(RecordValidationError::RrsigOriginalTtlTooLarge {
                    value: rrsig.original_ttl,
                });
            }
        }
        validate_rdata_wire(&self.rdata)
    }

    /// Preserves received advisory algorithm bytes while enforcing the other
    /// outbound record constraints. Local builders retain strict policy.
    pub(crate) fn validate_for_forwarding(&self) -> Result<(), RecordValidationError> {
        if self.rtype != RecordType::OPT {
            return self.validate();
        }
        if self.name != DomainName::root()
            || !matches!(self.class, ClassType::Unknown(_))
            || !matches!(self.rdata, RData::OPT(_))
        {
            return Err(RecordValidationError::InvalidRDataType);
        }
        let z = (self.ttl & 0x7fff) as u16;
        if z != 0 {
            return Err(RecordValidationError::NonzeroEdnsZ { value: z });
        }
        validate_rdata_forwarded(&self.rdata)
    }

    /// Validates a record received from the wire for safe generic handling.
    ///
    /// RFC 6891 requires receivers to ignore unknown EDNS flag bits. The bits
    /// remain present in the record so a caller inspecting the received OPT
    /// can observe the wire value. Locally authored OPT records must use
    /// [`Self::validate`], which requires those bits to be zero.
    pub fn validate_received(&self) -> Result<(), RecordValidationError> {
        if self.rtype != RecordType::OPT {
            return self.validate();
        }
        if self.name != DomainName::root()
            || !matches!(self.class, ClassType::Unknown(_))
            || !matches!(self.rdata, RData::OPT(_))
        {
            return Err(RecordValidationError::InvalidRDataType);
        }
        let RData::OPT(options) = &self.rdata else {
            unreachable!("OPT RDATA shape checked above");
        };
        validate_received_edns_options(options)
    }

    pub(crate) fn validate_locally_authored(&self) -> Result<(), RecordValidationError> {
        self.validate()?;
        if let RData::CAA(caa) = &self.rdata
            && caa.has_reserved_flags()
        {
            return Err(RecordValidationError::ReservedCaaFlags { value: caa.flags });
        }
        validate_dnskey_publication(&self.rdata)?;
        validate_nsec3_publication(&self.rdata)?;
        validate_csync_publication(&self.rdata)?;
        Ok(())
    }
}

/// Partitions records into validated RRSets, preserving first-seen set order.
pub(crate) fn rrsets_from_records(
    records: &[ResourceRecord],
) -> Result<Vec<RrSet>, RecordValidationError> {
    let mut sets: Vec<Vec<ResourceRecord>> = Vec::with_capacity(records.len());
    let mut set_indexes: HashMap<(DomainName, RecordType, ClassType), usize> =
        HashMap::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        if is_rrsig_type(record.rtype) {
            if records[..index]
                .iter()
                .any(|previous| same_record(previous, record))
            {
                return Err(RecordValidationError::DuplicateRecord);
            }
            sets.push(vec![record.clone()]);
        } else {
            let key = (record.name.clone(), record.rtype, record.class);
            if let Some(&set_index) = set_indexes.get(&key) {
                sets[set_index].push(record.clone());
            } else {
                let set_index = sets.len();
                sets.push(vec![record.clone()]);
                set_indexes.insert(key, set_index);
            }
        }
    }
    sets.into_iter().map(RrSet::try_from_records).collect()
}

/// Validates the zone-data constraints that can be determined from records
/// alone. Zone origin, SOA cardinality, and delegation rules require a
/// zone-aware database and are deliberately not assumed here.
///
/// Implements RFC 1035 §5.2 checks 1 (one class per zone) and the CNAME
/// exclusivity rules from RFC 1034 §3.6.2 as updated by RFC 4035 §2.5.
pub(crate) fn validate_zone_records(
    records: &[ResourceRecord],
) -> Result<(), RecordValidationError> {
    if let Some(record) = records.iter().find(|record| record.rtype.is_meta_type()) {
        return Err(RecordValidationError::MetaTypeInZone {
            value: record.rtype.into(),
        });
    }
    if let Some(caa) = records.iter().find_map(|record| match &record.rdata {
        RData::CAA(caa) if caa.has_reserved_flags() => Some(caa),
        _ => None,
    }) {
        return Err(RecordValidationError::ReservedCaaFlags { value: caa.flags });
    }
    for record in records {
        validate_dnskey_publication(&record.rdata)?;
        validate_nsec3_publication(&record.rdata)?;
        validate_csync_publication(&record.rdata)?;
    }
    let sets = rrsets_from_records(records)?;
    if let Some(first) = sets.first()
        && sets.iter().any(|set| set.class != first.class)
    {
        return Err(RecordValidationError::MixedZoneClass);
    }
    for set in &sets {
        if set.rtype == RecordType::CNAME && set.records.len() != 1 {
            return Err(RecordValidationError::MultipleCnameRecords);
        }
        if set.rtype == RecordType::CNAME
            && sets.iter().any(|other| {
                other.name.eq_dns(&set.name)
                    && other.class == set.class
                    && other.rtype != RecordType::CNAME
                    && !other.rtype.is_cname_companion()
            })
        {
            return Err(RecordValidationError::CnameWithOtherData);
        }
    }
    Ok(())
}

fn validate_dnskey_publication(rdata: &RData) -> Result<(), RecordValidationError> {
    let RData::DNSKEY(dnskey) = rdata else {
        return Ok(());
    };
    if dnskey.protocol != 3 {
        return Err(RecordValidationError::InvalidDnskeyProtocol {
            value: dnskey.protocol,
        });
    }
    if dnskey.flags & !(crate::Dnskey::ZONE_KEY_FLAG | crate::Dnskey::SECURE_ENTRY_POINT_FLAG) != 0
    {
        return Err(RecordValidationError::ReservedDnskeyFlags {
            value: dnskey.flags,
        });
    }
    if dnskey.flags & crate::Dnskey::SECURE_ENTRY_POINT_FLAG != 0
        && dnskey.flags & crate::Dnskey::ZONE_KEY_FLAG == 0
    {
        return Err(RecordValidationError::DnskeySepWithoutZoneKey);
    }
    Ok(())
}

fn validate_nsec3_publication(rdata: &RData) -> Result<(), RecordValidationError> {
    match rdata {
        RData::NSEC3(nsec3) if nsec3.flags & !crate::Nsec3::OPT_OUT_FLAG != 0 => {
            Err(RecordValidationError::ReservedNsec3Flags { value: nsec3.flags })
        }
        RData::NSEC3PARAM(parameters) if parameters.flags != 0 => {
            Err(RecordValidationError::NonzeroNsec3paramFlags {
                value: parameters.flags,
            })
        }
        _ => Ok(()),
    }
}

fn validate_csync_publication(rdata: &RData) -> Result<(), RecordValidationError> {
    let RData::CSYNC(csync) = rdata else {
        return Ok(());
    };
    if csync.unknown_flags() != 0 {
        return Err(RecordValidationError::ReservedCsyncFlags {
            value: csync.unknown_flags(),
        });
    }
    if let Some(value) = csync
        .type_bitmap
        .codes()
        .iter()
        .copied()
        .find(|code| matches!(code, 43 | 48 | 59 | 60 | 62))
    {
        return Err(RecordValidationError::ForbiddenCsyncType { value });
    }
    Ok(())
}

pub(crate) fn is_rrsig_type(rtype: RecordType) -> bool {
    matches!(u16::from(rtype), 24 | 46)
}

pub(crate) fn same_rrset_key(
    record: &ResourceRecord,
    name: &DomainName,
    rtype: RecordType,
    class: ClassType,
) -> bool {
    record.rtype == rtype && record.class == class && record.name.eq_dns(name)
}

pub(crate) fn same_record(left: &ResourceRecord, right: &ResourceRecord) -> bool {
    left.eq_dns(right)
}

#[cfg(test)]
mod tests;

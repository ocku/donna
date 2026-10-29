#[cfg(test)]
use dns::QueryType;
mod dnssec;
mod lookup;
mod nodata;
mod positive;
pub(crate) mod response;
mod types;
mod validation;

use dns::master::MasterFile;
use dns::{ClassType, DomainName, QClassType, Question, RData, RecordType, ResourceRecord};

use crate::{
    ZoneError,
    name::{dns_name_key_into, suffixes},
};
use dnssec::{NegativeResponsePrefix, Nsec3Index, NsecIndex};
use lookup::ZoneLookupIndex;
use nodata::NodataCache;
pub(crate) use positive::{InitialLookup, PositiveRecordRefs, PositiveSelection};
pub(crate) use types::Lookup;
use validation::validate_snapshot;

/// Stores an immutable, validated authoritative zone.
#[derive(Debug)]
pub struct Zone {
    pub(crate) apex: DomainName,
    pub(crate) class: ClassType,
    records: Vec<ResourceRecord>,
    soa: ResourceRecord,
    index: ZoneLookupIndex,
    nsec3_index: Option<Nsec3Index>,
    nsec_index: Option<NsecIndex>,
    has_dname: bool,
    has_nsec3param: bool,
    nsec_records: Vec<usize>,
    nxt_records: Vec<usize>,
    negative_prefix: NegativeResponsePrefix,
    nodata_budget: std::sync::atomic::AtomicU32,
}

impl Zone {
    /// Builds a validated authoritative zone from a parsed master file.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError`] if the master file is invalid or doesn't define a
    /// self-consistent authoritative zone at `apex`.
    pub fn from_master(apex: DomainName, master: MasterFile) -> Result<Self, ZoneError> {
        let (records, soa) = validate_snapshot(&apex, None, master)?;
        let class = soa.class;
        Ok(Self::new(apex, class, records, soa))
    }

    /// Returns the zone apex.
    #[must_use]
    pub fn apex(&self) -> &DomainName {
        &self.apex
    }

    /// Returns the zone's resource-record class.
    #[must_use]
    pub const fn class(&self) -> ClassType {
        self.class
    }

    /// Returns the complete validated zone snapshot in storage order.
    #[must_use]
    pub fn records(&self) -> &[ResourceRecord] {
        &self.records
    }

    pub(crate) fn has_same_snapshot(&self, other: &Self) -> bool {
        self.apex.eq_dns(&other.apex)
            && self.class == other.class
            && self.records.len() == other.records.len()
            && self.records.iter().all(|record| {
                other
                    .records
                    .iter()
                    .any(|candidate| record.ttl == candidate.ttl && record.eq_dns(candidate))
            })
    }

    fn new(
        apex: DomainName,
        class: ClassType,
        records: Vec<ResourceRecord>,
        soa: ResourceRecord,
    ) -> Self {
        let mut index = ZoneLookupIndex::new(&apex, &records);
        let mut nsec3_index = Nsec3Index::new(&apex, class, &records);
        let has_nsec3param = records
            .iter()
            .any(|record| record.rtype == RecordType::NSEC3PARAM);
        let has_dname = records
            .iter()
            .any(|record| record.rtype == RecordType::DNAME);
        if has_nsec3param && let Some(nsec3) = &mut nsec3_index {
            index.link_nsec3(&apex, &records, nsec3);
        }
        let mut zone = Self {
            apex,
            class,
            records,
            soa,
            index,
            nsec3_index,
            nsec_index: None,
            has_dname,
            has_nsec3param,
            nsec_records: Vec::new(),
            nxt_records: Vec::new(),
            negative_prefix: NegativeResponsePrefix::default(),
            nodata_budget: std::sync::atomic::AtomicU32::new(0),
        };
        for (i, record) in zone.records.iter().enumerate() {
            if record.class == zone.class
                && (record.rtype == RecordType::NSEC || u16::from(record.rtype) == 30)
                && zone.is_authoritative_owner(&record.name)
            {
                if record.rtype == RecordType::NSEC {
                    zone.nsec_records.push(i);
                } else {
                    zone.nxt_records.push(i);
                }
            }
        }
        zone.nsec_index = NsecIndex::new(&zone.records, &zone.nsec_records);
        zone.negative_prefix = zone.build_negative_response_prefix();
        zone
    }

    pub(crate) fn from_dynamic_records(
        apex: DomainName,
        class: ClassType,
        records: Vec<ResourceRecord>,
    ) -> Result<Self, ZoneError> {
        let (records, soa) = validate_snapshot(&apex, Some(class), MasterFile { records })?;
        Ok(Self::new(apex, class, records, soa))
    }

    pub(crate) fn lookup(&self, question: &Question) -> Lookup {
        match self.lookup_initial(question) {
            InitialLookup::Positive(selection) => Lookup::Answer(selection.into_owned()),
            InitialLookup::Final(lookup) => lookup,
        }
    }

    /// Whether this zone's authoritative traversal reaches a DNAME before
    /// any delegation for the supplied canonical name.
    pub(crate) fn redirects_by_dname_key(&self, key: &[u8]) -> bool {
        self.has_dname && matches!(self.index.select(key), lookup::NodeSelection::Dname(_))
    }

    pub(crate) fn nodata_cache(&self, name: &DomainName) -> Option<&NodataCache> {
        self.index.nodata_cache(name)
    }

    pub(crate) fn prepare_nodata(
        &self,
        cache: &NodataCache,
        query: &dns::Message,
        dnssec_ok: bool,
        authorities: &[&ResourceRecord],
    ) {
        cache.prepare(&self.nodata_budget, query, dnssec_ok, authorities);
    }

    /// Returns in-bailiwick A and AAAA glue associated with delegation NS records.
    pub(crate) fn referral_glue_records(&self, records: &[ResourceRecord]) -> Vec<ResourceRecord> {
        let mut additionals = Vec::new();
        for record in records {
            let RData::NS(target) = &record.rdata else {
                continue;
            };
            if !target.is_descendant_of(&record.name) {
                continue;
            }
            for address in self.address_records_at(target) {
                if !response::contains_record(&additionals, &address) {
                    additionals.push(address);
                }
            }
        }
        additionals
    }

    #[cfg(test)]
    pub(crate) fn transfer_records(&self) -> Vec<ResourceRecord> {
        self.transfer_records_iter().collect()
    }

    pub(crate) fn transfer_records_iter(&self) -> impl Iterator<Item = ResourceRecord> + '_ {
        std::iter::once(self.soa.clone())
            .chain(
                self.records
                    .iter()
                    .filter(|record| {
                        record.rtype != RecordType::SOA || !record.name.eq_dns(&self.apex)
                    })
                    .cloned(),
            )
            .chain(std::iter::once(self.soa.clone()))
    }

    pub(crate) fn soa(&self) -> &ResourceRecord {
        &self.soa
    }

    pub(crate) fn is_authoritative_owner(&self, name: &DomainName) -> bool {
        let mut storage = [0; 255];
        let key = dns_name_key_into(name, &mut storage);
        self.index
            .outermost_delegation_cut(key)
            .is_none_or(|cut| cut == key)
    }

    fn supports_class(&self, question: &Question) -> bool {
        match question.qclass {
            QClassType::Class(class) => class == self.class,
            QClassType::ANY => true,
            QClassType::Unknown(code) => self.class.value() == code,
        }
    }

    #[cfg(test)]
    fn lookup_owner_records<'a>(
        &self,
        records: impl Iterator<Item = &'a ResourceRecord> + Clone,
        qtype: QueryType,
        proof_owner: &DomainName,
    ) -> Lookup {
        let answers = lookup::records_of_type(records.clone(), qtype);
        if !answers.is_empty() {
            return Lookup::Answer(answers);
        }

        let cname = lookup::records_of_type(records, QueryType::CNAME);
        if let Some(target) = cname.iter().find_map(lookup::cname_target).cloned() {
            return Lookup::Cname {
                records: cname,
                target,
            };
        }
        Lookup::NoData {
            proof_owner: proof_owner.clone(),
        }
    }

    #[cfg(test)]
    fn delegation(&self, name: &DomainName) -> Option<Vec<ResourceRecord>> {
        let mut storage = [0; 255];
        let name = dns_name_key_into(name, &mut storage);
        let cut = self.index.outermost_delegation_cut(name)?;
        Some(self.name_servers_at(cut))
    }

    #[cfg(test)]
    fn name_servers_at(&self, name: &[u8]) -> Vec<ResourceRecord> {
        self.records_at_key(name)
            .into_iter()
            .filter(|record| record.rtype == RecordType::NS)
            .collect()
    }

    pub(super) fn address_records_at(&self, name: &DomainName) -> Vec<ResourceRecord> {
        if !name.is_descendant_of(&self.apex) {
            return Vec::new();
        }
        self.records_at(name)
            .into_iter()
            .filter(|record| matches!(record.rtype, RecordType::A | RecordType::AAAA))
            .collect()
    }

    #[cfg(test)]
    fn wildcard_records_at_closest_encloser(
        &self,
        name: &DomainName,
    ) -> Option<(DomainName, &[usize])> {
        let mut storage = [0; 255];
        let key = dns_name_key_into(name, &mut storage);
        for (index, suffix) in suffixes(key).enumerate() {
            if !self.index.node_exists_key(suffix) {
                continue;
            }
            let length = suffix.len() + 2;
            if length > 255 {
                return None;
            }
            let mut wildcard_key = [0; 255];
            wildcard_key[..2].copy_from_slice(&[1, b'*']);
            wildcard_key[2..length].copy_from_slice(suffix);
            // Most NXDOMAIN lookups have no wildcard at this encloser. Probe
            // the existing index before allocating an owned wildcard name.
            let wildcard_key = &wildcard_key[..length];
            // RFC 4592 section 4.9: an empty nonterminal wildcard still
            // exists and synthesizes NODATA, rather than NXDOMAIN.
            if !self.index.node_exists_key(wildcard_key) {
                return None;
            }
            let records = self.index.records_at_key(wildcard_key).unwrap_or(&[]);
            let closest = &name.as_ref()[index..];
            // The immutable source already owns the usual wildcard spelling.
            // Reuse it only on exact label equality; mixed-case expansion and
            // empty nonterminals retain the original constructed spelling.
            if let Some(&first) = records.first() {
                let owner = &self.records[first].name;
                if owner.as_ref().get(1..) == Some(closest) {
                    return Some((owner.clone(), records));
                }
            }
            let mut labels = Vec::with_capacity(closest.len() + 1);
            labels.push(b"*".to_vec());
            labels.extend_from_slice(closest);
            return Some((DomainName::from_labels(labels).ok()?, records));
        }
        None
    }

    fn closest_encloser_labels<'a>(&self, name: &'a DomainName) -> Option<&'a [Vec<u8>]> {
        let mut storage = [0; 255];
        let key = dns_name_key_into(name, &mut storage);
        suffixes(key).enumerate().find_map(|(index, suffix)| {
            self.index
                .node_exists_key(suffix)
                .then(|| &name.as_ref()[index..])
        })
    }

    fn wildcard_at_closest_encloser(&self, name: &DomainName) -> Option<DomainName> {
        let closest = self.closest_encloser_labels(name)?;
        let mut wildcard = Vec::with_capacity(closest.len() + 1);
        wildcard.push(b"*".to_vec());
        wildcard.extend_from_slice(closest);
        DomainName::from_labels(wildcard).ok()
    }

    #[cfg(test)]
    fn node_exists(&self, name: &DomainName) -> bool {
        self.index.node_exists(name)
    }

    fn records_at(&self, name: &DomainName) -> Vec<ResourceRecord> {
        let mut storage = [0; 255];
        let key = dns_name_key_into(name, &mut storage);
        self.records_at_key(key)
    }

    fn records_at_key(&self, name: &[u8]) -> Vec<ResourceRecord> {
        self.index
            .records_at_key(name)
            .into_iter()
            .flatten()
            .map(|&index| self.records[index].clone())
            .collect()
    }

    fn soa_minimum(&self) -> u32 {
        match self.soa.rdata {
            RData::SOA { minimum, .. } => minimum,
            _ => unreachable!("the zone SOA has SOA RDATA"),
        }
    }
}
#[cfg(test)]
mod tests;

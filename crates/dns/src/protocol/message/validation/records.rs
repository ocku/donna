//! RRset consistency checks with a small-message path and borrowed-key indexes.
use std::collections::HashMap;

use crate::protocol::resource_record::{same_record, same_rrset_key};
use crate::{ClassType, DomainName, RData, RecordType, RecordValidationError, ResourceRecord};

use super::helpers::{invalid_record, is_rrsig_type};
use super::{Message, MessageValidationError};

const LINEAR_LIMIT: usize = 32;

type Owner<'a> = (&'a DomainName, ClassType);
type Rrset<'a> = (&'a DomainName, RecordType, ClassType);
type Record<'a> = (&'a DomainName, RecordType, ClassType, &'a RData);

#[derive(Clone, Copy)]
struct Previous<'a> {
    section: &'static str,
    index: usize,
    record: &'a ResourceRecord,
    ttl: u32,
}

#[derive(Default)]
pub(super) struct RecordChecks<'a> {
    previous: PreviousRecords<'a>,
    indexed: Option<Indexes<'a>>,
}

#[derive(Default)]
struct PreviousRecords<'a> {
    inline: [Option<Previous<'a>>; 8],
    overflow: Vec<Previous<'a>>,
    len: usize,
}

impl<'a> PreviousRecords<'a> {
    fn len(&self) -> usize {
        self.len
    }

    fn clear(&mut self) {
        self.inline = [None; 8];
        self.overflow.clear();
        self.len = 0;
    }

    fn push(&mut self, previous: Previous<'a>) {
        if self.len < self.inline.len() {
            self.inline[self.len] = Some(previous);
        } else {
            self.overflow.push(previous);
        }
        self.len += 1;
    }

    fn get(&self, index: usize) -> Previous<'a> {
        if index < self.inline.len() {
            self.inline[index].expect("an indexed previous record is initialized")
        } else {
            self.overflow[index - self.inline.len()]
        }
    }

    fn iter(&self) -> impl Iterator<Item = &Previous<'a>> {
        self.inline[..self.len.min(self.inline.len())]
            .iter()
            .map(|previous| previous.as_ref().expect("the inline prefix is initialized"))
            .chain(self.overflow.iter())
    }
}

#[derive(Default)]
struct Indexes<'a> {
    rrsets: HashMap<Rrset<'a>, usize>,
    records: HashMap<Record<'a>, usize>,
    cnames: HashMap<Owner<'a>, usize>,
    ordinary: HashMap<Owner<'a>, usize>,
}

impl<'a> RecordChecks<'a> {
    pub(super) fn clear(&mut self) {
        self.previous.clear();
        self.indexed = None;
    }

    pub(super) fn push(&mut self, section: &'static str, index: usize, record: &'a ResourceRecord) {
        self.push_with_ttl(section, index, record, record.ttl);
    }

    pub(super) fn push_with_ttl(
        &mut self,
        section: &'static str,
        index: usize,
        record: &'a ResourceRecord,
        ttl: u32,
    ) {
        if self.indexed.is_none() && self.previous.len() == LINEAR_LIMIT {
            let mut indexes = Indexes::default();
            for (position, previous) in self.previous.iter().enumerate() {
                indexes.insert(previous.record, position);
            }
            self.indexed = Some(indexes);
        }
        if let Some(indexes) = &mut self.indexed {
            indexes.insert(record, self.previous.len());
        }
        self.previous.push(Previous {
            section,
            index,
            record,
            ttl,
        });
    }

    pub(super) fn validate(
        &self,
        message: &Message,
        section: &'static str,
        index: usize,
        record: &ResourceRecord,
        semantic_rcode: u16,
    ) -> Result<(), MessageValidationError> {
        self.validate_context(
            Some(message),
            section,
            index,
            record,
            record.ttl,
            semantic_rcode,
        )
    }

    /// Ordinary borrowed replies cannot contain transfer-boundary duplicates.
    pub(super) fn validate_nontransfer(
        &self,
        section: &'static str,
        index: usize,
        record: &ResourceRecord,
    ) -> Result<(), MessageValidationError> {
        self.validate_with_ttl(section, index, record, record.ttl)
    }

    pub(super) fn validate_with_ttl(
        &self,
        section: &'static str,
        index: usize,
        record: &ResourceRecord,
        ttl: u32,
    ) -> Result<(), MessageValidationError> {
        self.validate_context(None, section, index, record, ttl, 0)
    }

    fn validate_context(
        &self,
        message: Option<&Message>,
        section: &'static str,
        index: usize,
        record: &ResourceRecord,
        ttl: u32,
        semantic_rcode: u16,
    ) -> Result<(), MessageValidationError> {
        let current = Previous {
            section,
            index,
            record,
            ttl,
        };
        if let Some(indexes) = &self.indexed {
            // Only the earliest RRset member, exact duplicate, or conflicting
            // CNAME owner can change the result. Visit them in wire order to
            // preserve which error the original linear traversal reported.
            for position in indexes.candidates(record).into_iter().flatten() {
                validate_pair(
                    message,
                    self.previous.get(position),
                    current,
                    semantic_rcode,
                )?;
            }
        } else {
            for &previous in self.previous.iter() {
                validate_pair(message, previous, current, semantic_rcode)?;
            }
        }
        Ok(())
    }
}

impl<'a> Indexes<'a> {
    fn insert(&mut self, record: &'a ResourceRecord, position: usize) {
        let owner = (&record.name, record.class);
        self.rrsets
            .entry((&record.name, record.rtype, record.class))
            .or_insert(position);
        self.records
            .entry((&record.name, record.rtype, record.class, &record.rdata))
            .or_insert(position);
        if record.rtype == RecordType::CNAME {
            self.cnames.entry(owner).or_insert(position);
        } else if !record.rtype.is_cname_companion() {
            self.ordinary.entry(owner).or_insert(position);
        }
    }

    fn candidates(&self, record: &ResourceRecord) -> [Option<usize>; 3] {
        let owner = (&record.name, record.class);
        let conflict = if record.rtype == RecordType::CNAME {
            self.ordinary.get(&owner)
        } else if !record.rtype.is_cname_companion() {
            self.cnames.get(&owner)
        } else {
            None
        };
        let mut candidates = [
            self.rrsets
                .get(&(&record.name, record.rtype, record.class))
                .copied(),
            self.records
                .get(&(&record.name, record.rtype, record.class, &record.rdata))
                .copied(),
            conflict.copied(),
        ];
        candidates.sort_unstable();
        // Duplicate candidates are harmless and retain fixed-size storage.
        candidates
    }
}

fn validate_pair(
    message: Option<&Message>,
    previous: Previous<'_>,
    current: Previous<'_>,
    semantic_rcode: u16,
) -> Result<(), MessageValidationError> {
    let Previous {
        section,
        index,
        record,
        ttl,
    } = current;
    let fail = |error| invalid_record(section, index, error);
    if same_rrset_key(
        record,
        &previous.record.name,
        previous.record.rtype,
        previous.record.class,
    ) {
        if is_rrsig_type(record.rtype) {
            if same_record(previous.record, record) {
                return Err(fail(RecordValidationError::DuplicateRecord));
            }
            return Ok(());
        }
        if section != previous.section {
            return Err(fail(RecordValidationError::DuplicateRrSetAcrossSections));
        }
        if ttl != previous.ttl {
            return Err(fail(RecordValidationError::InconsistentTtl {
                expected: previous.ttl,
                actual: ttl,
            }));
        }
        if same_record(previous.record, record) {
            if message.is_some_and(|message| {
                message.is_transfer_boundary_soa_duplicate(
                    previous.section,
                    previous.index,
                    section,
                    index,
                    record,
                    semantic_rcode,
                )
            }) {
                return Ok(());
            }
            return Err(fail(RecordValidationError::DuplicateRecord));
        }
        if record.rtype == RecordType::CNAME {
            return Err(fail(RecordValidationError::MultipleCnameRecords));
        }
    } else if ((record.rtype == RecordType::CNAME && !previous.record.rtype.is_cname_companion())
        || (previous.record.rtype == RecordType::CNAME && !record.rtype.is_cname_companion()))
        && record.class == previous.record.class
        && record.name.eq_dns(&previous.record.name)
    {
        return Err(fail(RecordValidationError::CnameWithOtherData));
    }
    Ok(())
}

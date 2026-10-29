//! Immutable initial selections shared by structured and borrowed UDP replies.
use super::{Lookup, Zone, lookup};
use dns::{DomainName, QueryType, Question, ResourceRecord};
use smallvec::SmallVec;

pub(crate) type PositiveRecordRefs<'a> = SmallVec<[(&'a ResourceRecord, &'a DomainName); 8]>;

pub(crate) enum InitialLookup<'a> {
    Positive(PositiveSelection<'a>),
    Final(Lookup),
}

pub(crate) struct PositiveSelection<'a> {
    zone: &'a Zone,
    indices: &'a [usize],
    qtype: QueryType,
    expanded_owner: Option<DomainName>,
}

impl PositiveSelection<'_> {
    pub(crate) fn source_indices(&self) -> &[usize] {
        self.indices
    }

    fn iter(&self) -> impl Iterator<Item = (&ResourceRecord, &DomainName)> {
        self.indices.iter().filter_map(|&index| {
            let record = &self.zone.records[index];
            lookup::matches_query(record, self.qtype)
                .then_some((record, self.expanded_owner.as_ref().unwrap_or(&record.name)))
        })
    }

    pub(crate) fn references(&self) -> PositiveRecordRefs<'_> {
        self.iter().collect()
    }

    pub(crate) fn into_owned(self) -> Vec<ResourceRecord> {
        self.iter()
            .map(|(record, owner)| {
                let mut record = record.clone();
                record.name = owner.clone();
                record
            })
            .collect()
    }
}

impl Zone {
    pub(crate) fn lookup_initial(&self, question: &Question) -> InitialLookup<'_> {
        let mut storage = [0; 255];
        let key = crate::name::dns_name_key_into(&question.qname, &mut storage);
        self.lookup_initial_key(question, key)
    }

    /// `key` is the canonical spelling of this already checked question. UDP
    /// routing builds it once and shares it with the immutable node traversal.
    pub(crate) fn lookup_initial_key(&self, question: &Question, key: &[u8]) -> InitialLookup<'_> {
        if !self.supports_class(question) {
            return InitialLookup::Final(Lookup::NoData {
                proof_owner: question.qname.clone(),
            });
        }
        match self.index.select(key) {
            lookup::NodeSelection::Dname(indices) => {
                let record = indices
                    .iter()
                    .map(|&i| &self.records[i])
                    .find(|record| matches!(record.rdata, dns::RData::DNAME(_)))
                    .expect("DNAME index refers to a DNAME record");
                let dns::RData::DNAME(destination) = &record.rdata else {
                    unreachable!()
                };
                InitialLookup::Final(Lookup::Dname {
                    record: record.clone(),
                    target: question
                        .qname
                        .dname_substitute(&record.name, destination)
                        .ok()
                        .flatten(),
                })
            }
            lookup::NodeSelection::Delegation { key: cut, records } => {
                if question.qtype.value() == 43 && cut == key {
                    self.select_initial(question, records, &question.qname, None, false)
                } else {
                    InitialLookup::Final(Lookup::Referral(
                        records
                            .iter()
                            .map(|&i| &self.records[i])
                            .filter(|r| r.rtype == dns::RecordType::NS)
                            .cloned()
                            .collect(),
                    ))
                }
            }
            lookup::NodeSelection::Exact(indices) => {
                self.select_initial(question, indices, &question.qname, None, true)
            }
            lookup::NodeSelection::Wildcard { skipped, records } => {
                let closest = &question.qname.as_ref()[skipped..];
                let wildcard = if let Some(&first) = records.first()
                    && self.records[first].name.as_ref().get(1..) == Some(closest)
                {
                    self.records[first].name.clone()
                } else {
                    let mut labels = Vec::with_capacity(closest.len() + 1);
                    labels.push(b"*".to_vec());
                    labels.extend_from_slice(closest);
                    DomainName::from_labels(labels).expect("indexed wildcard fits DNS limits")
                };
                self.select_initial(
                    question,
                    records,
                    &wildcard,
                    Some(question.qname.clone()),
                    true,
                )
            }
            lookup::NodeSelection::Missing => InitialLookup::Final(Lookup::NameError),
        }
    }

    fn select_initial<'a>(
        &'a self,
        question: &Question,
        indices: &'a [usize],
        proof_owner: &DomainName,
        expanded_owner: Option<DomainName>,
        allow_cname: bool,
    ) -> InitialLookup<'a> {
        if indices
            .iter()
            .any(|&i| lookup::matches_query(&self.records[i], question.qtype))
        {
            return InitialLookup::Positive(PositiveSelection {
                zone: self,
                indices,
                qtype: question.qtype,
                expanded_owner,
            });
        }
        if !allow_cname {
            return InitialLookup::Final(Lookup::NoData {
                proof_owner: proof_owner.clone(),
            });
        }
        let mut records =
            lookup::records_of_type(indices.iter().map(|&i| &self.records[i]), QueryType::CNAME);
        let Some(target) = records.iter().find_map(lookup::cname_target).cloned() else {
            return InitialLookup::Final(Lookup::NoData {
                proof_owner: proof_owner.clone(),
            });
        };
        if let Some(owner) = expanded_owner {
            for record in &mut records {
                record.name = owner.clone();
            }
        }
        InitialLookup::Final(Lookup::Cname { records, target })
    }
}

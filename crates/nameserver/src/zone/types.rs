use dns::{DomainName, ResourceRecord};

pub(crate) enum Lookup {
    Answer(Vec<ResourceRecord>),
    Cname {
        records: Vec<ResourceRecord>,
        target: DomainName,
    },
    Dname {
        record: ResourceRecord,
        target: Option<DomainName>,
    },
    Referral(Vec<ResourceRecord>),
    NameError,
    NoData {
        proof_owner: DomainName,
    },
}

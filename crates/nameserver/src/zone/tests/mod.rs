use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use dns::{
    ClassType, Csync, DomainName, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord, TypeBitmap,
};

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn ds(marker: u8) -> RData {
    RData::DS(dns::Ds {
        key_tag: 1,
        algorithm: 15,
        digest_type: 2,
        digest: vec![marker; 32],
    })
}

fn record(name: DomainName, rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name,
        rtype,
        class: ClassType::IN,
        ttl: 60,
        rdata,
    }
}

fn zone(records: Vec<ResourceRecord>, soa: ResourceRecord) -> Zone {
    Zone::new(name(&["example"]), ClassType::IN, records, soa)
}

fn soa() -> ResourceRecord {
    record(
        name(&["example"]),
        RecordType::SOA,
        RData::SOA {
            mname: name(&["ns", "example"]),
            rname: name(&["hostmaster", "example"]),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 300,
        },
    )
}

fn csync(serial: u32, owner: DomainName) -> ResourceRecord {
    record(
        owner,
        RecordType::CSYNC,
        RData::CSYNC(Csync {
            soa_serial: serial,
            flags: 3,
            type_bitmap: TypeBitmap::new([1, 2, 28]).unwrap(),
        }),
    )
}

mod csync;
mod denial_index;
mod lookup;
mod negative_prefix;
mod signature_index;
mod validation;
mod wildcard_and_aliases;
mod wildcard_proofs;

mod wildcard_selection;

mod prelinked_nsec3;

mod nsec3_visibility;

mod positive_selection;

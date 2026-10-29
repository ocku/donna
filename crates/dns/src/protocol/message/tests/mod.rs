use crate::{Caa, DomainName, Edns, FromWire, IntoWire, RData};

use super::*;

fn a_record(ttl: u32, last_octet: u8) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::A,
        class: crate::ClassType::IN,
        ttl,
        rdata: crate::RData::A(std::net::Ipv4Addr::new(192, 0, 2, last_octet)),
    }
}

fn rrsig_record(ttl: u32, signature: u8) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::RRSIG,
        class: crate::ClassType::IN,
        ttl,
        rdata: rrsig_rdata(1, 60, signature),
    }
}

fn rrsig_rdata(type_covered: u16, original_ttl: u32, signature: u8) -> crate::RData {
    crate::RData::RRSIG(crate::Rrsig {
        type_covered,
        algorithm: 15,
        labels: 1,
        original_ttl,
        signature_expiration: 2,
        signature_inception: 1,
        key_tag: 1,
        signer_name: DomainName::root(),
        signature: vec![signature],
    })
}

fn legacy_sig_record(name: DomainName, ttl: u32, signature: u8) -> ResourceRecord {
    ResourceRecord {
        name,
        rtype: RecordType::SIG,
        class: crate::ClassType::IN,
        ttl,
        rdata: crate::RData::SIG(crate::Sig {
            type_covered: 1,
            algorithm: 1,
            labels: 1,
            original_ttl: ttl,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: DomainName::root(),
            signature: vec![signature],
        }),
    }
}

mod authoritative_negatives;
mod cname_responses;
mod rrsets_and_transfers;
mod structure_and_queries;

mod indexed_validation;

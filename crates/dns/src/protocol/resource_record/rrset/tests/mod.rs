use std::net::Ipv4Addr;

use super::*;
use crate::{Caa, Csync, Dnskey, Ds, Nsec3, Nsec3param, Rrsig, TypeBitmap};

fn record(ttl: u32, address: [u8; 4]) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl,
        rdata: RData::A(Ipv4Addr::from(address)),
    }
}

fn hinfo_record(cpu: &[u8], os: &[u8]) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::HINFO,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::HINFO {
            cpu: cpu.to_vec(),
            os: os.to_vec(),
        },
    }
}

fn rrsig_record(ttl: u32, signature: u8) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl,
        rdata: RData::RRSIG(crate::Rrsig {
            type_covered: 1,
            algorithm: 15,
            labels: 1,
            original_ttl: 60,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: DomainName::root(),
            signature: vec![signature],
        }),
    }
}

fn dnssec_record(rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_dotted("owner.example").unwrap(),
        rtype,
        class: ClassType::IN,
        ttl: 60,
        rdata,
    }
}

mod comparisons_and_zone_rules;
mod construction_and_dnssec;
mod csync;
mod publication_constraints;

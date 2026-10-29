use std::net::Ipv4Addr;

use dns::{Headers, QueryType, RCode, RecordType};

use super::*;

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn question(labels: &[&str]) -> Question {
    Question {
        qname: name(labels),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn record(owner: DomainName, rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype,
        class: ClassType::IN,
        ttl: 60,
        rdata,
    }
}

fn a_record(owner: DomainName, last_octet: u8) -> ResourceRecord {
    record(
        owner,
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
    )
}

fn cname_record(owner: DomainName, target: DomainName) -> ResourceRecord {
    record(owner, RecordType::CNAME, RData::CNAME(target))
}

fn soa_record(zone: DomainName) -> ResourceRecord {
    record(
        zone,
        RecordType::SOA,
        RData::SOA {
            mname: name(&["ns", "example"]),
            rname: name(&["hostmaster", "example"]),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 30,
        },
    )
}

fn rrsig_record(owner: DomainName, type_covered: RecordType, signature: u8) -> ResourceRecord {
    record(
        owner,
        RecordType::RRSIG,
        RData::RRSIG(dns::Rrsig {
            type_covered: u16::from(type_covered),
            algorithm: 15,
            labels: 2,
            original_ttl: 60,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: name(&["example"]),
            signature: vec![signature],
        }),
    )
}

fn nsec_record(owner: DomainName, next_label: &str) -> ResourceRecord {
    record(
        owner,
        RecordType::NSEC,
        RData::NSEC(dns::Nsec {
            next_domain_name: name(&[next_label, "example"]),
            type_bitmap: dns::TypeBitmap::new([1, 46, 47]).unwrap(),
        }),
    )
}

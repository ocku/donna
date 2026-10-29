use super::*;

pub(super) fn rrsig(type_covered: RecordType, ttl: u32, signature: u8) -> ResourceRecord {
    ResourceRecord {
        name: dns::DomainName::from_labels(vec![b"www".to_vec(), b"example".to_vec()]).unwrap(),
        rtype: RecordType::RRSIG,
        class: dns::ClassType::IN,
        ttl,
        rdata: RData::RRSIG(dns::Rrsig {
            type_covered: u16::from(type_covered),
            algorithm: 15,
            labels: 2,
            original_ttl: ttl,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: dns::DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            signature: vec![signature],
        }),
    }
}

pub(super) fn a_record() -> ResourceRecord {
    ResourceRecord {
        name: dns::DomainName::from_labels(vec![b"www".to_vec(), b"example".to_vec()]).unwrap(),
        rtype: RecordType::A,
        class: dns::ClassType::IN,
        ttl: 60,
        rdata: RData::A(std::net::Ipv4Addr::LOCALHOST),
    }
}

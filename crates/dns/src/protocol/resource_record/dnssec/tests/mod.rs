use std::net::Ipv4Addr;

use p256::pkcs8::EncodePrivateKey;

use super::*;

fn name(value: &str) -> DomainName {
    DomainName::from_dotted(value).unwrap()
}

fn rrsig(labels: u8) -> Rrsig {
    Rrsig {
        type_covered: u16::from(crate::RecordType::A),
        algorithm: 15,
        labels,
        original_ttl: 3_600,
        signature_expiration: 2,
        signature_inception: 1,
        key_tag: 0x1234,
        signer_name: name("ExAmPlE.TeSt"),
        signature: vec![0xaa],
    }
}

fn a_record(owner: &str, last_octet: u8) -> ResourceRecord {
    ResourceRecord {
        name: name(owner),
        rtype: crate::RecordType::A,
        class: crate::ClassType::IN,
        ttl: 120,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
    }
}

mod bitmap_signatures;
mod canonical_and_signing;
mod ds_sha1_equivalence;
mod nsec3_hash_fixed;
mod nsec_and_keys;
mod p256_equivalence;
mod signed_denial;

use canonical_and_signing::nsec3_record;

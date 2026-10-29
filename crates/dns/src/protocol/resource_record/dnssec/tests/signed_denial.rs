use crate::{FromWire, Message, RData, RecordType};

#[test]
fn independently_signed_compact_denial_preserves_nxname_during_verification() {
    // Authoritative Cloudflare example.com response captured on 2026-10-26
    // for does-not-exist-donna-audit.example.com A with DO=1, and its DNSKEYs.
    // Both signatures were independently verified with dnspython. The NSEC
    // bitmap contains RRSIG, NSEC, and RFC 9824 NXNAME (TYPE128). Keep the
    // original signed packets to detect any decode/canonicalization mutation.
    let response =
        Message::from_wire(include_bytes!("fixtures/example-com-compact-denial.bin")).unwrap();
    let keys = Message::from_wire(include_bytes!("fixtures/example-com-dnskeys.bin")).unwrap();
    // 2026-10-26 16:00 UTC, within the captured signatures' validity interval.
    let now = 1_793_030_400;
    let mut verified = Vec::new();
    for record in &response.authorities {
        let RData::RRSIG(signature) = &record.rdata else {
            continue;
        };
        let rrset = response
            .authorities
            .iter()
            .filter(|rr| {
                rr.name.eq_dns(&record.name)
                    && rr.class == record.class
                    && u16::from(rr.rtype) == signature.type_covered
            })
            .cloned()
            .collect::<Vec<_>>();
        let key_record = keys
            .answers
            .iter()
            .find(|rr| {
                rr.name.eq_dns(&signature.signer_name)
                    && matches!(&rr.rdata, RData::DNSKEY(key) if key.key_tag() == signature.key_tag)
            })
            .unwrap();
        let RData::DNSKEY(key) = &key_record.rdata else {
            unreachable!()
        };
        signature
            .verify(&rrset, &key_record.name, key, now)
            .unwrap();
        verified.push(signature.type_covered);
    }
    verified.sort_unstable();
    assert_eq!(
        verified,
        [u16::from(RecordType::SOA), u16::from(RecordType::NSEC)]
    );
}

//! Full authentication must not make different covered types evict each other.
use super::{
    fixtures::{resolver, signed_record_fixture},
    support::name,
};
use dns::{DnssecSecurityStatus, QueryType, RData, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};

#[tokio::test]
async fn independently_authenticated_a_aaaa_and_txt_survive_alternating_cache_reads() {
    let owner = name(&["dual", "example"]);
    let (transport, anchor, _) = signed_record_fixture(
        false,
        owner.clone(),
        QueryType::A,
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 42)),
    );
    let resolver = resolver(transport, anchor);
    let mut expected = Vec::new();
    for (kind, rtype, data) in [
        (
            QueryType::A,
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 42)),
        ),
        (
            QueryType::AAAA,
            RecordType::AAAA,
            RData::AAAA(Ipv6Addr::LOCALHOST),
        ),
        (
            QueryType::TXT,
            RecordType::TXT,
            RData::TXT(vec![b"independent signed data".to_vec()]),
        ),
    ] {
        let (fixture, _, question) =
            signed_record_fixture(false, owner.clone(), kind, rtype, data.clone());
        let mut reply = fixture.answer;
        let validation = resolver
            .validate_dnssec_response_with_deadline(&question, &mut reply, None)
            .await
            .unwrap();
        assert_eq!(validation.status, DnssecSecurityStatus::Secure);
        reply.headers.ad = true;
        resolver
            .cache_validated_response_with_dnames_backend(&reply, &question, &validation)
            .await
            .unwrap();
        expected.push((question, rtype, data));
    }
    for _ in 0..4 {
        for (question, rtype, data) in &expected {
            let cached = resolver
                .cached_client_response(question)
                .unwrap()
                .expect("all validated types remain admitted")
                .response;
            assert!(cached.headers.ad);
            assert!(
                cached
                    .answers
                    .iter()
                    .any(|rr| rr.rtype == *rtype && rr.rdata == *data)
            );
            let signatures: Vec<_> = cached
                .answers
                .iter()
                .filter_map(|rr| match &rr.rdata {
                    RData::RRSIG(sig) => Some(sig.type_covered),
                    _ => None,
                })
                .collect();
            assert_eq!(signatures, [question.qtype.value()]);
        }
    }
}

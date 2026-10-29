use super::*;

#[tokio::test]
async fn nsec_empty_nonterminal_nodata_returns_signed_covering_descendant_proof() {
    let apex = name(&["example"]);
    let alias = name(&["alias-empty", "example"]);
    let empty = name(&["empty", "example"]);
    let deep = name(&["deep", "empty", "example"]);
    let leaf = name(&["leaf", "deep", "empty", "example"]);
    let mut records = vec![
        record(
            alias.clone(),
            RecordType::CNAME,
            RData::CNAME(empty.clone()),
        ),
        rrsig(alias.clone(), RecordType::CNAME, 2),
        record(
            leaf.clone(),
            RecordType::TXT,
            RData::TXT(vec![b"creates empty ancestors".to_vec()]),
        ),
        record(
            alias.clone(),
            RecordType::NSEC,
            RData::NSEC(dns::Nsec {
                next_domain_name: leaf,
                type_bitmap: dns::TypeBitmap::new([5, 46, 47]).unwrap(),
            }),
        ),
        rrsig(alias.clone(), RecordType::NSEC, 2),
        rrsig(apex.clone(), RecordType::SOA, 1),
    ];
    // An unrelated NSEC is insufficient for an empty owner's denial.
    records.push(record(
        apex.clone(),
        RecordType::NSEC,
        RData::NSEC(dns::Nsec {
            next_domain_name: alias.clone(),
            type_bitmap: dns::TypeBitmap::new([2, 6, 46, 47]).unwrap(),
        }),
    ));
    records.push(rrsig(apex.clone(), RecordType::NSEC, 1));
    let server = NameServer::new();
    server
        .install(make_zone(apex.clone(), ClassType::IN, 30, records))
        .await
        .unwrap();
    for (qname, qtype, target) in [
        (empty.clone(), QueryType::A, empty.clone()),
        (deep.clone(), QueryType::AAAA, deep),
        (alias, QueryType::A, empty),
    ] {
        let response = server
            .handle(query_with_do(qname.clone(), qtype, true))
            .await;
        assert!(response.headers.aa);
        assert_eq!(response.headers.rcode, RCode::Ok);
        let proofs = response
            .authorities
            .iter()
            .filter(|r| r.rtype == RecordType::NSEC)
            .collect::<Vec<_>>();
        assert_eq!(proofs.len(), 1);
        let proof = proofs[0];
        assert!(matches!(&proof.rdata, RData::NSEC(nsec)
            if nsec.covers_name(&proof.name, &target)
                && nsec.next_domain_name.is_descendant_of(&target)
                && !nsec.next_domain_name.eq_dns(&target)));
        assert!(
            response
                .authorities
                .iter()
                .any(|r| r.name.eq_dns(&proof.name)
                    && matches!(&r.rdata, RData::RRSIG(sig) if sig.type_covered == 47))
        );
        assert!(
            response
                .authorities
                .iter()
                .any(|r| r.rtype == RecordType::SOA && r.ttl == 30)
        );
        assert!(response.into_wire().is_ok());
        let plain = server.handle(query_with_do(qname, qtype, false)).await;
        assert!(plain.authorities.iter().all(|r| r.rtype == RecordType::SOA));
    }
}

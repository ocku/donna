use super::*;

fn signed_wildcard_zone(nsec3: bool) -> Zone {
    let apex = name(&["example"]);
    let wildcard = name(&["*", "wild", "example"]);
    let lower = name(&["a", "wild", "example"]);
    let upper = name(&["z", "wild", "example"]);
    let alias = name(&["alias", "example"]);
    let mut records = vec![
        record(
            alias.clone(),
            RecordType::CNAME,
            RData::CNAME(name(&["m", "wild", "example"])),
        ),
        rrsig(alias.clone(), RecordType::CNAME, 2),
    ];
    for owner in [&wildcard, &lower, &upper] {
        records.push(record(
            owner.clone(),
            RecordType::TXT,
            RData::TXT(vec![b"text only".to_vec()]),
        ));
    }
    let base = make_zone(apex.clone(), ClassType::IN, 30, records);
    if nsec3 {
        return add_nsec3_chain(base, false);
    }
    let mut records = base.records().to_vec();
    records.push(rrsig(apex.clone(), RecordType::SOA, 1));
    // The wildcard NSEC ends at a.wild, so it cannot prove m.wild or
    // p.q.wild absent. The separate a.wild -> z.wild interval must appear.
    let owners = [apex.clone(), alias, wildcard, lower, upper];
    for (index, owner) in owners.iter().enumerate() {
        let types = match index {
            0 => vec![2, 6, 46, 47],
            1 => vec![5, 46, 47],
            _ => vec![16, 46, 47],
        };
        records.push(record(
            owner.clone(),
            RecordType::NSEC,
            RData::NSEC(dns::Nsec {
                next_domain_name: owners[(index + 1) % owners.len()].clone(),
                type_bitmap: dns::TypeBitmap::new(types).unwrap(),
            }),
        ));
        records.push(rrsig(
            owner.clone(),
            RecordType::NSEC,
            owner.as_ref().len() as u8,
        ));
    }
    Zone::from_master(apex, MasterFile { records }).unwrap()
}

fn assert_denial_signatures_and_ttl(response: &Message, denial_type: RecordType) {
    let soa = response
        .authorities
        .iter()
        .find(|r| r.rtype == RecordType::SOA)
        .unwrap();
    assert_eq!(soa.ttl, 30);
    let soa_signature = response
        .authorities
        .iter()
        .find(|r| matches!(&r.rdata, RData::RRSIG(sig) if sig.type_covered == 6))
        .unwrap();
    assert_eq!(soa_signature.ttl, 30);
    for proof in response
        .authorities
        .iter()
        .filter(|r| r.rtype == denial_type)
    {
        assert!(response.authorities.iter().any(|r| r.name.eq_dns(&proof.name)
            && matches!(&r.rdata, RData::RRSIG(sig) if sig.type_covered == u16::from(denial_type))));
        assert_eq!(
            response
                .authorities
                .iter()
                .filter(|r| r.eq_dns(proof))
                .count(),
            1
        );
    }
    assert!(response.clone().into_wire().is_ok());
}

#[tokio::test]
async fn wildcard_nodata_nsec_contains_distinct_type_and_expansion_witnesses() {
    let server = NameServer::new();
    server.install(signed_wildcard_zone(false)).await.unwrap();
    let wildcard = name(&["*", "wild", "example"]);
    for expanded in [
        name(&["m", "wild", "example"]),
        name(&["p", "q", "wild", "example"]),
    ] {
        let response = server
            .handle(query_with_do(expanded.clone(), QueryType::A, true))
            .await;
        assert_eq!(response.headers.rcode, RCode::Ok);
        assert!(response.headers.aa);
        assert!(response.answers.is_empty());
        let type_proof = response
            .authorities
            .iter()
            .find(|r| r.rtype == RecordType::NSEC && r.name.eq_dns(&wildcard))
            .unwrap();
        assert!(
            matches!(&type_proof.rdata, RData::NSEC(nsec) if !nsec.covers_name(&type_proof.name, &expanded))
        );
        assert!(response.authorities.iter().any(|r| r.rtype == RecordType::NSEC
            && !r.name.eq_dns(&wildcard)
            && matches!(&r.rdata, RData::NSEC(nsec) if nsec.covers_name(&r.name, &expanded))));
        assert_denial_signatures_and_ttl(&response, RecordType::NSEC);
    }
}

#[tokio::test]
async fn wildcard_nodata_nsec3_contains_complete_encloser_and_wildcard_proofs() {
    let apex = name(&["example"]);
    let wildcard = name(&["*", "wild", "example"]);
    let closest = name(&["wild", "example"]);
    let zone = signed_wildcard_zone(true);
    let chain = zone
        .records()
        .iter()
        .filter(|r| r.rtype == RecordType::NSEC3)
        .cloned()
        .collect::<Vec<_>>();
    let server = NameServer::new();
    server.install(zone).await.unwrap();
    for expanded in [
        name(&["m", "wild", "example"]),
        name(&["p", "q", "wild", "example"]),
    ] {
        let response = server
            .handle(query_with_do(expanded.clone(), QueryType::A, true))
            .await;
        assert_eq!(response.headers.rcode, RCode::Ok);
        assert!(response.answers.is_empty());
        let encloser =
            dns::find_nsec3_closest_encloser(&chain, &apex, ClassType::IN, &expanded, 0).unwrap();
        assert!(encloser.closest_encloser.eq_dns(&closest));
        let wildcard_proof = chain.iter().find(|r|
            matches!(&r.rdata, RData::NSEC3(nsec3) if nsec3.matches_name(&r.name, &apex, &wildcard, 0).unwrap())).unwrap();
        assert!(!wildcard_proof.eq_dns(&chain[encloser.matching_record]));
        for proof in [
            wildcard_proof,
            &chain[encloser.matching_record],
            &chain[encloser.covering_record],
        ] {
            assert!(response.authorities.iter().any(|r| r.eq_dns(proof)));
        }
        assert_denial_signatures_and_ttl(&response, RecordType::NSEC3);
    }
}

#[tokio::test]
async fn cname_to_wildcard_nodata_preserves_expanded_target_and_do_policy() {
    let alias = name(&["alias", "example"]);
    let target = name(&["m", "wild", "example"]);
    let wildcard = name(&["*", "wild", "example"]);
    for nsec3 in [false, true] {
        let server = NameServer::new();
        server.install(signed_wildcard_zone(nsec3)).await.unwrap();
        let direct = server
            .handle(query_with_do(target.clone(), QueryType::A, true))
            .await;
        let via_alias = server
            .handle(query_with_do(alias.clone(), QueryType::A, true))
            .await;
        assert!(
            via_alias
                .answers
                .iter()
                .any(|r| r.rtype == RecordType::CNAME)
        );
        for proof in &direct.authorities {
            assert!(via_alias.authorities.iter().any(|r| r.eq_dns(proof)));
        }
        let unsigned = server
            .handle(query_with_do(target.clone(), QueryType::A, false))
            .await;
        assert!(
            unsigned
                .authorities
                .iter()
                .all(|r| r.rtype == RecordType::SOA)
        );
        // A literal wildcard owner needs its type proof without expansion.
        let literal = server
            .handle(query_with_do(wildcard.clone(), QueryType::A, true))
            .await;
        assert_eq!(
            literal
                .authorities
                .iter()
                .filter(|r| r.rtype
                    == if nsec3 {
                        RecordType::NSEC3
                    } else {
                        RecordType::NSEC
                    })
                .count(),
            1
        );
    }
}

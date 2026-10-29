use super::*;

fn delegation(apex: DomainName, class: ClassType, has_ds: bool) -> Zone {
    let child = name(&["child", "example"]);
    let mut records = vec![class_record(
        child.clone(),
        RecordType::NS,
        class,
        RData::NS(DomainName::root()),
    )];
    if has_ds {
        records.push(class_record(
            child,
            RecordType::DS,
            class,
            RData::DS(dns::Ds {
                key_tag: 1,
                algorithm: 15,
                digest_type: 2,
                digest: vec![5; 32],
            }),
        ));
    }
    make_zone(apex, class, 30, records)
}

fn assert_nodata(response: &Message, apex: &DomainName, class: ClassType) {
    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert!(response.answers.is_empty());
    let soa = response
        .authorities
        .iter()
        .find(|record| record.rtype == RecordType::SOA)
        .unwrap();
    assert!(soa.name.eq_dns(apex));
    assert_eq!(soa.class, class);
    assert_eq!(soa.ttl, 30);
    assert!(response.clone().into_wire().is_ok());
}

#[tokio::test]
async fn cohosted_ds_selects_parent_for_both_positive_and_negative_answers() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    for has_ds in [false, true] {
        let server = NameServer::new();
        server
            .install(delegation(apex.clone(), ClassType::IN, has_ds))
            .await
            .unwrap();
        server
            .install(make_zone(child.clone(), ClassType::IN, 300, vec![]))
            .await
            .unwrap();
        let response = server
            .handle(query_with_do(child.clone(), QueryType::DS, true))
            .await;
        if has_ds {
            assert!(response.headers.aa);
            assert_eq!(response.answers.len(), 1);
            assert_eq!(response.answers[0].rtype, RecordType::DS);
        } else {
            assert_nodata(&response, &apex, ClassType::IN);
        }
        let child_soa = server
            .handle(query_with_do(child.clone(), QueryType::SOA, false))
            .await;
        assert!(child_soa.answers[0].name.eq_dns(&child));
    }
}

#[tokio::test]
async fn child_only_and_other_class_parent_preserve_child_side_ds_nodata() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    let server = NameServer::new();
    server
        .install(make_zone(child.clone(), ClassType::IN, 30, vec![]))
        .await
        .unwrap();
    assert_nodata(
        &server
            .handle(query_with_do(child.clone(), QueryType::DS, false))
            .await,
        &child,
        ClassType::IN,
    );
    server
        .install(delegation(apex, ClassType::CH, true))
        .await
        .unwrap();
    assert_nodata(
        &server
            .handle(query_with_do(child.clone(), QueryType::DS, false))
            .await,
        &child,
        ClassType::IN,
    );
    let mut ch = query_with_do(child.clone(), QueryType::DS, false);
    ch.questions[0].qclass = QClassType::Class(ClassType::CH);
    let answer = server.handle(ch).await;
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].class, ClassType::CH);
}

#[tokio::test]
async fn root_ds_has_no_parent_and_returns_root_nodata() {
    let server = NameServer::new();
    server
        .install(make_zone(
            DomainName::root(),
            ClassType::IN,
            30,
            vec![record(
                DomainName::root(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 53)),
            )],
        ))
        .await
        .unwrap();
    assert_nodata(
        &server
            .handle(query_with_do(DomainName::root(), QueryType::DS, false))
            .await,
        &DomainName::root(),
        ClassType::IN,
    );
}

#[tokio::test]
async fn delegation_ds_denial_includes_signed_nsec() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    let base = delegation(apex.clone(), ClassType::IN, false);
    let mut records = base.records().to_vec();
    records.extend([
        record(
            child.clone(),
            RecordType::NSEC,
            RData::NSEC(dns::Nsec {
                next_domain_name: apex.clone(),
                type_bitmap: dns::TypeBitmap::new([2, 46, 47]).unwrap(),
            }),
        ),
        rrsig(child.clone(), RecordType::NSEC, 2),
        rrsig(apex.clone(), RecordType::SOA, 1),
    ]);
    let server = NameServer::new();
    server
        .install(Zone::from_master(apex.clone(), MasterFile { records }).unwrap())
        .await
        .unwrap();
    let response = server
        .handle(query_with_do(child.clone(), QueryType::DS, true))
        .await;
    assert_nodata(&response, &apex, ClassType::IN);
    assert!(
        response
            .authorities
            .iter()
            .any(|r| r.rtype == RecordType::NSEC && r.name.eq_dns(&child))
    );
    for covered in [RecordType::SOA, RecordType::NSEC] {
        assert!(response.authorities.iter().any(
            |r| matches!(&r.rdata, RData::RRSIG(sig) if sig.type_covered == u16::from(covered))
        ));
    }
    let unsigned = server
        .handle(query_with_do(child, QueryType::DS, false))
        .await;
    assert!(
        unsigned
            .authorities
            .iter()
            .all(|r| r.rtype == RecordType::SOA)
    );
}

#[tokio::test]
async fn delegation_ds_nsec3_denial_contains_complete_opt_out_proof() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    for opt_out in [false, true] {
        let base = delegation(apex.clone(), ClassType::IN, false);
        let mut records = base.records().to_vec();
        // This owner makes the next-closer covering RR distinct from the
        // apex matching RR, so omitting either part fails the regression.
        records.push(record(
            name(&["a", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        let base = Zone::from_master(apex.clone(), MasterFile { records }).unwrap();
        let zone = add_nsec3_chain(base, opt_out);
        let chain: Vec<_> = zone
            .records()
            .iter()
            .filter(|r| r.rtype == RecordType::NSEC3)
            .cloned()
            .collect();
        let server = NameServer::new();
        server.install(zone).await.unwrap();
        let response = server
            .handle(query_with_do(child.clone(), QueryType::DS, true))
            .await;
        assert_nodata(&response, &apex, ClassType::IN);
        let expected = if opt_out {
            let proof =
                dns::find_nsec3_closest_encloser(&chain, &apex, ClassType::IN, &child, 0).unwrap();
            assert_ne!(proof.matching_record, proof.covering_record);
            assert!(
                matches!(&chain[proof.covering_record].rdata, RData::NSEC3(nsec3) if nsec3.opt_out())
            );
            vec![&chain[proof.matching_record], &chain[proof.covering_record]]
        } else {
            vec![chain.iter().find(|r| matches!(&r.rdata, RData::NSEC3(nsec3) if nsec3.matches_name(&r.name, &apex, &child, 0).unwrap())).unwrap()]
        };
        let referral = server
            .handle(query_with_do(
                name(&["host", "child", "example"]),
                QueryType::A,
                true,
            ))
            .await;
        assert!(!referral.headers.aa);
        for proof in expected {
            assert!(referral.authorities.iter().any(|r| r.eq_dns(proof)));
            assert!(response.authorities.iter().any(|r| r.eq_dns(proof)));
            assert!(
                response
                    .authorities
                    .iter()
                    .any(|r| r.name.eq_dns(&proof.name)
                        && matches!(&r.rdata, RData::RRSIG(sig) if sig.type_covered == 50))
            );
        }
    }
}

#[tokio::test]
async fn distant_ancestor_with_intervening_delegation_is_not_the_ds_parent() {
    let child = name(&["child", "example"]);
    let server = NameServer::new();
    server
        .install(make_zone(
            DomainName::root(),
            ClassType::IN,
            300,
            vec![
                record(
                    DomainName::root(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                ),
                record(
                    name(&["example"]),
                    RecordType::NS,
                    RData::NS(DomainName::root()),
                ),
            ],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(child.clone(), ClassType::IN, 30, vec![]))
        .await
        .unwrap();
    assert_nodata(
        &server
            .handle(query_with_do(child.clone(), QueryType::DS, false))
            .await,
        &child,
        ClassType::IN,
    );
    // A DS query for an ordinary child-zone owner still uses that child.
    let below = server
        .handle(query_with_do(
            name(&["www", "child", "example"]),
            QueryType::DS,
            false,
        ))
        .await;
    assert_eq!(below.headers.rcode, RCode::NameError);
    assert!(
        below
            .authorities
            .iter()
            .any(|r| r.rtype == RecordType::SOA && r.name.eq_dns(&child))
    );
}

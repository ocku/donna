use super::*;

#[test]
fn preserves_zone_ttls_except_for_the_negative_response_soa() {
    let mut source = record(
        name(&["www", "example"]),
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    );
    source.ttl = 120;
    let mut authority_soa = soa();
    authority_soa.ttl = 900;
    let zone = zone(vec![source.clone()], authority_soa.clone());

    assert_eq!(zone.negative_response_soa().ttl, 300);
    let transfer = zone.transfer_records();
    assert_eq!(transfer.first().unwrap().ttl, 900);
    assert_eq!(transfer[1].ttl, 120);
    assert_eq!(transfer.last().unwrap().ttl, 900);

    assert_eq!(zone.soa.ttl, authority_soa.ttl);
    assert_eq!(zone.records[0].ttl, source.ttl);
}

#[test]
fn maila_returns_md_and_mf_but_excludes_mx() {
    let owner = name(&["mail", "example"]);
    let zone = zone(
        vec![
            record(
                owner.clone(),
                RecordType::MD,
                RData::MD(name(&["delivery", "example"])),
            ),
            record(
                owner.clone(),
                RecordType::MF,
                RData::MF(name(&["forwarder", "example"])),
            ),
            record(
                owner.clone(),
                RecordType::MX,
                RData::MX {
                    preference: 10,
                    exchange: name(&["exchange", "example"]),
                },
            ),
        ],
        soa(),
    );
    let question = Question {
        qname: owner,
        qtype: QueryType::MAILA,
        qclass: QClassType::Class(ClassType::IN),
    };

    let Lookup::Answer(records) = zone.lookup(&question) else {
        panic!("MAILA lookup should return MD and MF records");
    };
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| record.rtype == RecordType::MD));
    assert!(records.iter().any(|record| record.rtype == RecordType::MF));
    assert!(records.iter().all(|record| record.rtype != RecordType::MX));
}

#[test]
fn unknown_query_type_matches_the_same_numeric_record_type() {
    let owner = name(&["opaque", "example"]);
    let zone = zone(
        vec![record(
            owner.clone(),
            RecordType::Unknown(65_000),
            RData::Unknown(vec![1, 2, 3]),
        )],
        soa(),
    );

    let matching = Question {
        qname: owner.clone(),
        qtype: QueryType::Unknown(65_000),
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(matches!(zone.lookup(&matching), Lookup::Answer(records)
        if records.len() == 1 && records[0].rdata == RData::Unknown(vec![1, 2, 3])));

    let different = Question {
        qname: owner,
        qtype: QueryType::Unknown(65_001),
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(matches!(
        zone.lookup(&different),
        Lookup::NoData { proof_owner } if proof_owner.eq_dns(&different.qname)
    ));
}

#[test]
fn serves_parent_side_ds_at_an_exact_delegation_owner() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    let ds_rdata = ds(5);
    let zone = Zone::from_master(
        apex.clone(),
        MasterFile {
            records: vec![
                soa(),
                record(apex, RecordType::NS, RData::NS(DomainName::root())),
                record(
                    child.clone(),
                    RecordType::NS,
                    RData::NS(name(&["ns", "elsewhere"])),
                ),
                record(child.clone(), RecordType::DS, ds_rdata.clone()),
            ],
        },
    )
    .unwrap();
    let question = Question {
        qname: child.clone(),
        qtype: QueryType::DS,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(matches!(zone.lookup(&question), Lookup::Answer(records)
        if records.len() == 1
            && records[0].name.eq_dns(&child)
            && records[0].rtype == RecordType::DS
            && records[0].rdata == ds_rdata));
    assert!(
        zone.transfer_records()
            .iter()
            .any(|record| { record.name.eq_dns(&child) && record.rtype == RecordType::DS })
    );
}

#[test]
fn preserves_referrals_for_other_queries_at_or_below_a_delegation() {
    let child = name(&["child", "example"]);
    let nested = name(&["nested", "child", "example"]);
    let zone = zone(
        vec![
            record(
                child.clone(),
                RecordType::NS,
                RData::NS(name(&["ns", "elsewhere"])),
            ),
            record(child.clone(), RecordType::DS, ds(3)),
            record(
                nested.clone(),
                RecordType::NS,
                RData::NS(name(&["ns", "other"])),
            ),
            record(nested.clone(), RecordType::DS, ds(6)),
        ],
        soa(),
    );

    for qtype in [
        QueryType::A,
        QueryType::AAAA,
        QueryType::NS,
        QueryType::RRSIG,
        QueryType::ANY,
    ] {
        let question = Question {
            qname: child.clone(),
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        };
        assert!(matches!(zone.lookup(&question), Lookup::Referral(records)
            if records.len() == 1 && records[0].rtype == RecordType::NS));
    }

    let below_cut = Question {
        qname: nested,
        qtype: QueryType::DS,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(matches!(zone.lookup(&below_cut), Lookup::Referral(records)
        if records.len() == 1 && records[0].rtype == RecordType::NS));
}

#[test]
fn a_ds_query_at_a_delegation_without_ds_returns_parent_nodata() {
    let child = name(&["child", "example"]);
    let zone = zone(
        vec![record(
            child.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "elsewhere"])),
        )],
        soa(),
    );
    let question = Question {
        qname: child.clone(),
        qtype: QueryType::DS,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(
        matches!(zone.lookup(&question), Lookup::NoData { proof_owner }
        if proof_owner.eq_dns(&child))
    );
}

#[test]
fn ds_queries_at_ordinary_owners_follow_normal_lookup_behavior() {
    let with_ds = name(&["secured", "example"]);
    let without_ds = name(&["ordinary", "example"]);
    let zone = zone(
        vec![
            record(with_ds.clone(), RecordType::DS, ds(1)),
            record(
                without_ds.clone(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            ),
        ],
        soa(),
    );

    let matching = Question {
        qname: with_ds,
        qtype: QueryType::DS,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(matches!(zone.lookup(&matching), Lookup::Answer(records)
        if records.len() == 1 && records[0].rtype == RecordType::DS));

    let no_data = Question {
        qname: without_ds,
        qtype: QueryType::DS,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(matches!(
        zone.lookup(&no_data),
        Lookup::NoData { proof_owner } if proof_owner.eq_dns(&no_data.qname)
    ));
}

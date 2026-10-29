use super::*;

#[test]
fn requires_glue_for_in_bailiwick_delegation_servers() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    let nameserver = name(&["ns", "child", "example"]);
    let mut records = vec![
        soa(),
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "example"])),
        ),
        record(child, RecordType::NS, RData::NS(nameserver.clone())),
    ];

    assert!(super::super::validation::validate_ownership_and_delegations(&apex, &records).is_err());

    records.push(record(
        nameserver,
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 53)),
    ));
    assert!(super::super::validation::validate_ownership_and_delegations(&apex, &records).is_ok());
}

#[test]
fn permits_out_of_bailiwick_delegation_servers_without_glue() {
    let apex = name(&["example"]);
    let records = vec![
        soa(),
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "example"])),
        ),
        record(
            name(&["child", "example"]),
            RecordType::NS,
            RData::NS(name(&["ns", "elsewhere"])),
        ),
    ];

    assert!(super::super::validation::validate_ownership_and_delegations(&apex, &records).is_ok());
}

#[test]
fn rejects_non_delegation_data_exactly_at_a_zone_cut() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    let records = vec![
        soa(),
        record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        record(
            child.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "elsewhere"])),
        ),
        record(
            child,
            RecordType::TXT,
            RData::TXT(vec![b"child data".to_vec()]),
        ),
    ];

    let error = Zone::from_master(apex, MasterFile { records }).unwrap_err();
    assert!(error.to_string().contains("zone cut"));
}

#[test]
fn rejects_invalid_soa_primary_names() {
    let apex = name(&["example"]);
    for invalid in [DomainName::root(), apex.clone()] {
        let mut invalid_soa = soa();
        let RData::SOA { mname, .. } = &mut invalid_soa.rdata else {
            unreachable!()
        };
        *mname = invalid;
        let records = vec![
            invalid_soa,
            record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        ];
        let error = Zone::from_master(apex.clone(), MasterFile { records }).unwrap_err();
        assert!(error.to_string().contains("MNAME"));
    }

    let primary = name(&["primary", "example"]);
    let mut alias_soa = soa();
    let RData::SOA { mname, .. } = &mut alias_soa.rdata else {
        unreachable!()
    };
    *mname = primary.clone();
    let records = vec![
        alias_soa,
        record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        record(
            primary,
            RecordType::CNAME,
            RData::CNAME(name(&["canonical", "elsewhere"])),
        ),
    ];
    let error = Zone::from_master(apex, MasterFile { records }).unwrap_err();
    assert!(error.to_string().contains("alias"));
}

#[test]
fn rejects_non_apex_soa_records() {
    let apex = name(&["example"]);
    let mut child_soa = soa();
    child_soa.name = name(&["child", "example"]);
    let records = vec![
        soa(),
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "example"])),
        ),
        child_soa,
    ];

    let error = Zone::from_master(apex, MasterFile { records }).unwrap_err();
    assert!(error.to_string().contains("visible SOA"));
}

#[test]
fn retains_occluded_names_for_axfr_but_hides_them_from_lookup() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    let nested = name(&["grand", "child", "example"]);
    let hidden = name(&["www", "grand", "child", "example"]);
    let mut hidden_soa = soa();
    hidden_soa.name = nested.clone();
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
                record(
                    nested.clone(),
                    RecordType::NS,
                    RData::NS(name(&["ns", "other"])),
                ),
                hidden_soa,
                record(
                    hidden.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ),
            ],
        },
    )
    .unwrap();
    let question = Question {
        qname: hidden.clone(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(matches!(zone.lookup(&question), Lookup::Referral(records)
        if records.len() == 1 && records[0].name.eq_dns(&child)));
    let transfer = zone.transfer_records();
    assert!(transfer.first().unwrap().name.eq_dns(&name(&["example"])));
    assert_eq!(transfer.first().unwrap().rtype, RecordType::SOA);
    assert!(transfer.last().unwrap().name.eq_dns(&name(&["example"])));
    assert_eq!(transfer.last().unwrap().rtype, RecordType::SOA);
    assert_eq!(
        transfer
            .iter()
            .filter(|record| record.rtype == RecordType::SOA)
            .count(),
        3
    );
    assert!(
        transfer
            .iter()
            .any(|record| { record.name.eq_dns(&nested) && record.rtype == RecordType::NS })
    );
    assert!(
        transfer
            .iter()
            .any(|record| { record.name.eq_dns(&nested) && record.rtype == RecordType::SOA })
    );
    assert!(
        transfer
            .iter()
            .any(|record| { record.name.eq_dns(&hidden) && record.rtype == RecordType::A })
    );
}

#[test]
fn occluded_cname_does_not_make_a_visible_target_an_alias() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    let target = name(&["mail", "child", "example"]);
    let records = vec![
        soa(),
        record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        record(
            apex.clone(),
            RecordType::MX,
            RData::MX {
                preference: 10,
                exchange: target.clone(),
            },
        ),
        record(child, RecordType::NS, RData::NS(name(&["ns", "elsewhere"]))),
        record(
            target,
            RecordType::CNAME,
            RData::CNAME(name(&["canonical", "elsewhere"])),
        ),
    ];

    Zone::from_master(apex, MasterFile { records }).unwrap();
}

#[test]
fn accepts_apex_soa_primary_when_it_is_an_addressable_hostname() {
    let apex = name(&["example"]);
    for address in [
        record(
            apex.clone(),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ),
        record(
            apex.clone(),
            RecordType::AAAA,
            RData::AAAA(Ipv6Addr::LOCALHOST),
        ),
    ] {
        let mut primary_soa = soa();
        let RData::SOA { mname, .. } = &mut primary_soa.rdata else {
            unreachable!()
        };
        *mname = apex.clone();
        let records = vec![
            primary_soa,
            address,
            record(apex.clone(), RecordType::NS, RData::NS(apex.clone())),
        ];
        assert!(Zone::from_master(apex.clone(), MasterFile { records }).is_ok());
    }
}

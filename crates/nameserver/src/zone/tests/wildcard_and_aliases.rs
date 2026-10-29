use super::*;

#[test]
fn synthesizes_wildcard_records_at_the_closest_encloser() {
    let query_name = name(&["www", "wild", "example"]);
    let zone = zone(
        vec![record(
            name(&["*", "wild", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 99)),
        )],
        soa(),
    );
    let question = Question {
        qname: query_name.clone(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(matches!(zone.lookup(&question), Lookup::Answer(records)
        if records.len() == 1 && records[0].name.eq_dns(&query_name)));
}

#[test]
fn wildcard_nodata_retains_the_wildcard_source_as_its_proof_owner() {
    let query_name = name(&["www", "wild", "example"]);
    let wildcard = name(&["*", "wild", "example"]);
    let zone = zone(
        vec![record(
            wildcard.clone(),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 99)),
        )],
        soa(),
    );
    let question = Question {
        qname: query_name,
        qtype: QueryType::TXT,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(matches!(
        zone.lookup(&question),
        Lookup::NoData { proof_owner } if proof_owner.eq_dns(&wildcard)
    ));
}

#[test]
fn permits_a_literal_asterisk_below_a_wildcard_owner() {
    let apex = name(&["example"]);
    let owner = name(&["*", "*", "example"]);
    let records = vec![
        soa(),
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "example"])),
        ),
        record(
            name(&["ns", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ),
        record(owner, RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 1))),
    ];

    // RFC 1034 recommends that a wildcard's suffix not contain another '*',
    // but RFC 2181 section 11 requires servers to accept arbitrary labels.
    // Only the leading label is a wildcard; the second '*' remains literal.
    let zone = Zone::from_master(apex, MasterFile { records }).unwrap();
    let question = Question {
        qname: name(&["host", "*", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(matches!(zone.lookup(&question), Lookup::Answer(records)
        if records.len() == 1 && records[0].name.eq_dns(&question.qname)));
}

#[test]
fn permits_an_asterisk_as_a_literal_non_leftmost_label() {
    let apex = name(&["example"]);
    let records = vec![
        soa(),
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "example"])),
        ),
        record(
            name(&["ns", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ),
        record(
            name(&["host", "*", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ),
    ];

    Zone::from_master(apex, MasterFile { records }).unwrap();
}

#[test]
fn rejects_locally_provable_ptr_ns_and_mx_alias_targets_case_insensitively() {
    let apex = name(&["example"]);
    let alias = name(&["alias", "example"]);
    for reference in [
        record(
            apex.clone(),
            RecordType::PTR,
            RData::PTR(name(&["ALIAS", "EXAMPLE"])),
        ),
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ALIAS", "EXAMPLE"])),
        ),
        record(
            apex.clone(),
            RecordType::MX,
            RData::MX {
                preference: 10,
                exchange: name(&["ALIAS", "EXAMPLE"]),
            },
        ),
    ] {
        let mut records = vec![
            soa(),
            record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
            record(
                alias.clone(),
                RecordType::CNAME,
                RData::CNAME(name(&["canonical", "example"])),
            ),
        ];
        records.push(reference);

        let error = Zone::from_master(apex.clone(), MasterFile { records }).unwrap_err();
        assert!(error.to_string().contains("target must not be an alias"));
    }
}

#[test]
fn rejects_authoritative_in_zone_ns_and_mx_targets_without_addresses() {
    let apex = name(&["example"]);
    for reference in [
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "example"])),
        ),
        record(
            apex.clone(),
            RecordType::MX,
            RData::MX {
                preference: 10,
                exchange: name(&["mail", "example"]),
            },
        ),
    ] {
        let mut records = vec![
            soa(),
            record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        ];
        records.push(reference);

        let error = Zone::from_master(apex.clone(), MasterFile { records }).unwrap_err();
        assert!(error.to_string().contains("requires an address record"));
    }
}

#[test]
fn accepts_authoritative_in_zone_ns_and_mx_targets_with_only_aaaa() {
    let apex = name(&["example"]);
    for (reference, target) in [
        (
            record(
                apex.clone(),
                RecordType::NS,
                RData::NS(name(&["ns", "example"])),
            ),
            name(&["ns", "example"]),
        ),
        (
            record(
                apex.clone(),
                RecordType::MX,
                RData::MX {
                    preference: 10,
                    exchange: name(&["mail", "example"]),
                },
            ),
            name(&["mail", "example"]),
        ),
    ] {
        let records = vec![
            soa(),
            record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
            reference,
            record(target, RecordType::AAAA, RData::AAAA(Ipv6Addr::LOCALHOST)),
        ];

        assert!(Zone::from_master(apex.clone(), MasterFile { records }).is_ok());
    }
}

#[test]
fn validates_srv_targets_and_allows_root_to_signal_unavailable_service() {
    let apex = name(&["example"]);
    let service = name(&["_ldap", "_tcp", "example"]);
    let target = name(&["ldap", "example"]);
    let srv = |target| {
        record(
            service.clone(),
            RecordType::SRV,
            RData::SRV {
                priority: 10,
                weight: 5,
                port: 389,
                target,
            },
        )
    };
    let base = || {
        vec![
            soa(),
            record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        ]
    };

    let mut without_address = base();
    without_address.push(srv(target.clone()));
    let error = Zone::from_master(
        apex.clone(),
        MasterFile {
            records: without_address,
        },
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("SRV target requires an address record")
    );

    let mut alias_target = base();
    alias_target.extend([
        srv(target.clone()),
        record(
            target.clone(),
            RecordType::CNAME,
            RData::CNAME(name(&["canonical", "example"])),
        ),
    ]);
    let error = Zone::from_master(
        apex.clone(),
        MasterFile {
            records: alias_target,
        },
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("SRV target must not be an alias")
    );

    let mut addressed = base();
    addressed.extend([
        srv(target.clone()),
        record(target, RecordType::AAAA, RData::AAAA(Ipv6Addr::LOCALHOST)),
    ]);
    assert!(Zone::from_master(apex.clone(), MasterFile { records: addressed }).is_ok());

    let mut unavailable = base();
    unavailable.push(srv(DomainName::root()));
    assert!(
        Zone::from_master(
            apex,
            MasterFile {
                records: unavailable
            }
        )
        .is_ok()
    );
}

#[test]
fn rejects_other_data_at_a_cname_owner() {
    let apex = name(&["example"]);
    let alias = name(&["alias", "example"]);
    let records = vec![
        soa(),
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "example"])),
        ),
        record(
            alias.clone(),
            RecordType::CNAME,
            RData::CNAME(name(&["target", "example"])),
        ),
        record(alias, RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 1))),
    ];

    let error = Zone::from_master(apex, MasterFile { records }).unwrap_err();
    assert!(error.to_string().contains("CNAME"));
}

#[test]
fn qtype_any_returns_every_record_at_the_owner() {
    let owner = name(&["host", "example"]);
    let zone = zone(
        vec![
            record(
                owner.clone(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            ),
            record(
                owner.clone(),
                RecordType::TXT,
                RData::TXT(vec![b"text".to_vec()]),
            ),
        ],
        soa(),
    );
    let question = Question {
        qname: owner,
        qtype: QueryType::ANY,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(matches!(zone.lookup(&question), Lookup::Answer(records)
        if records.len() == 2));
}

#[test]
fn mailb_returns_mb_mg_and_mr() {
    let owner = name(&["mail", "example"]);
    let zone = zone(
        vec![
            record(
                owner.clone(),
                RecordType::MB,
                RData::MB(name(&["mailbox", "example"])),
            ),
            record(
                owner.clone(),
                RecordType::MG,
                RData::MG(name(&["group", "example"])),
            ),
            record(
                owner.clone(),
                RecordType::MR,
                RData::MR(name(&["rename", "example"])),
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
        qtype: QueryType::MAILB,
        qclass: QClassType::Class(ClassType::IN),
    };

    let Lookup::Answer(records) = zone.lookup(&question) else {
        panic!("MAILB lookup should return MB, MG, and MR records");
    };
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| matches!(
        record.rtype,
        RecordType::MB | RecordType::MG | RecordType::MR
    )));
}

#[test]
fn lookups_match_owner_names_case_insensitively() {
    let owner = name(&["www", "example"]);
    let zone = zone(
        vec![record(
            owner,
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )],
        soa(),
    );
    let question = Question {
        qname: name(&["WWW", "EXAMPLE"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(matches!(zone.lookup(&question), Lookup::Answer(records)
        if records.len() == 1));
}

#[test]
fn existing_empty_non_terminal_blocks_wildcard_synthesis() {
    let zone = zone(
        vec![
            record(
                name(&["*", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 99)),
            ),
            record(
                name(&["child", "present", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            ),
        ],
        soa(),
    );
    let question = Question {
        qname: name(&["present", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(matches!(
        zone.lookup(&question),
        Lookup::NoData { proof_owner } if proof_owner.eq_dns(&question.qname)
    ));
}

#[test]
fn returns_cname_as_a_continuation_for_non_cname_queries() {
    let alias = name(&["alias", "example"]);
    let target = name(&["target", "example"]);
    let zone = zone(
        vec![record(
            alias.clone(),
            RecordType::CNAME,
            RData::CNAME(target.clone()),
        )],
        soa(),
    );
    let question = Question {
        qname: alias,
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    assert!(matches!(
        zone.lookup(&question),
        Lookup::Cname { target: found, .. } if found.eq_dns(&target)
    ));
}

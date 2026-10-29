use super::*;

#[test]
fn zone_accepts_one_csync_at_the_apex() {
    let apex = name(&["example"]);
    let records = vec![
        soa(),
        record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        csync(1, apex.clone()),
    ];
    let zone = Zone::from_master(apex.clone(), MasterFile { records }).unwrap();
    let question = Question {
        qname: apex,
        qtype: QueryType::CSYNC,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(matches!(zone.lookup(&question), Lookup::Answer(records)
        if records.len() == 1 && records[0].rtype == RecordType::CSYNC));
}

#[test]
fn zone_rejects_multiple_or_non_apex_csync_records() {
    let apex = name(&["example"]);
    let base = vec![
        soa(),
        record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
    ];

    let mut multiple = base.clone();
    multiple.extend([csync(1, apex.clone()), csync(2, apex.clone())]);
    let error = Zone::from_master(apex.clone(), MasterFile { records: multiple }).unwrap_err();
    assert!(error.to_string().contains("at most one CSYNC"));

    let mut non_apex = base;
    non_apex.push(csync(1, name(&["child", "example"])));
    let error = Zone::from_master(apex, MasterFile { records: non_apex }).unwrap_err();
    assert!(error.to_string().contains("located at its apex"));
}

#[test]
fn dynamic_zone_snapshot_rechecks_csync_publisher_rules() {
    let apex = name(&["example"]);
    let mut unsafe_csync = csync(1, apex.clone());
    let RData::CSYNC(csync) = &mut unsafe_csync.rdata else {
        unreachable!()
    };
    csync.flags = 0x8000;
    let records = vec![
        soa(),
        record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        unsafe_csync,
    ];
    let error = Zone::from_dynamic_records(apex, ClassType::IN, records).unwrap_err();
    let error = error.to_string();
    assert!(error.contains("reserved") && error.contains("flags"));
}

#[test]
fn master_and_dynamic_snapshots_reject_transaction_sig0_records() {
    let apex = name(&["example"]);
    let transaction_sig = record(
        DomainName::root(),
        RecordType::SIG,
        RData::SIG(dns::Sig {
            type_covered: 0,
            algorithm: 15,
            labels: 0,
            original_ttl: 0,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: name(&["key", "example"]),
            signature: vec![1],
        }),
    );
    let records = vec![
        soa(),
        record(apex.clone(), RecordType::NS, RData::NS(DomainName::root())),
        transaction_sig,
    ];

    let master_error = Zone::from_master(
        apex.clone(),
        MasterFile {
            records: records.clone(),
        },
    )
    .unwrap_err();
    assert!(master_error.to_string().contains("transaction-only SIG(0)"));

    let dynamic_error = Zone::from_dynamic_records(apex, ClassType::IN, records).unwrap_err();
    assert!(
        dynamic_error
            .to_string()
            .contains("transaction-only SIG(0)")
    );
}

mod concurrency;

use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use dns::master::MasterFile;
use dns::{
    ClassType, DomainName, Headers, Message, OpCode, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord,
};

use crate::{NameServer, NameServerConfig, UpdatePersistence, UpdatePersistenceError, Zone};

#[derive(Debug, Default)]
struct MemoryPersistence {
    snapshots: Mutex<Vec<Vec<ResourceRecord>>>,
}

impl UpdatePersistence for MemoryPersistence {
    fn persist<'future>(
        &'future self,
        zone: &'future Zone,
    ) -> transport::BoxFuture<'future, Result<(), UpdatePersistenceError>> {
        Box::pin(async move {
            self.snapshots.lock().unwrap().push(zone.records().to_vec());
            Ok(())
        })
    }
}

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn record(owner: DomainName, rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype,
        class: ClassType::IN,
        ttl: 300,
        rdata,
    }
}

fn base_records() -> Vec<ResourceRecord> {
    let apex = name(&["example"]);
    vec![
        record(
            apex.clone(),
            RecordType::SOA,
            RData::SOA {
                mname: name(&["primary", "invalid"]),
                rname: DomainName::root(),
                serial: 1,
                refresh: 60,
                retry: 60,
                expire: 3_600,
                minimum: 300,
            },
        ),
        record(apex, RecordType::NS, RData::NS(DomainName::root())),
        record(
            name(&["www", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ),
    ]
}

fn zone_with(extra: impl IntoIterator<Item = ResourceRecord>) -> Zone {
    let mut records = base_records();
    records.extend(extra);
    Zone::from_master(name(&["example"]), MasterFile { records }).unwrap()
}

fn zone_with_serial(serial: u32) -> Zone {
    let mut records = base_records();
    let RData::SOA {
        serial: current, ..
    } = &mut records[0].rdata
    else {
        unreachable!("base zone starts with an SOA")
    };
    *current = serial;
    Zone::from_master(name(&["example"]), MasterFile { records }).unwrap()
}

fn soa(serial: u32) -> ResourceRecord {
    record(
        name(&["example"]),
        RecordType::SOA,
        RData::SOA {
            mname: name(&["primary", "invalid"]),
            rname: DomainName::root(),
            serial,
            refresh: 60,
            retry: 60,
            expire: 3_600,
            minimum: 300,
        },
    )
}

fn server(persistence: Arc<MemoryPersistence>) -> NameServer {
    NameServer::with_config(NameServerConfig {
        update_persistence: Some(persistence),
        allow_insecure_updates: true,
        ..NameServerConfig::default()
    })
}

fn update(operations: impl IntoIterator<Item = ResourceRecord>) -> Message {
    Message::builder()
        .headers(Headers {
            opcode: OpCode::Update,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .authorities(operations)
        .build()
        .unwrap()
}

fn delete_rrset(owner: DomainName, rtype: RecordType) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype,
        class: ClassType::Unknown(255),
        ttl: 0,
        rdata: RData::Unknown(Vec::new()),
    }
}

async fn assert_not_published(server: &NameServer, question: Question) {
    let response = server
        .handle(Message::builder().questions([question]).build().unwrap())
        .await;
    assert!(response.answers.is_empty());
}

#[tokio::test]
async fn content_changes_to_a_currently_signed_zone_are_refused_without_persistence() {
    let persistence = Arc::new(MemoryPersistence::default());
    let server = server(Arc::clone(&persistence));
    let signed_owner = name(&["www", "example"]);
    server
        .install(zone_with([record(
            signed_owner,
            RecordType::RRSIG,
            RData::RRSIG(dns::Rrsig {
                type_covered: u16::from(RecordType::A),
                algorithm: 8,
                labels: 2,
                original_ttl: 300,
                signature_expiration: u32::MAX,
                signature_inception: 0,
                key_tag: 1,
                signer_name: name(&["example"]),
                signature: vec![1],
            }),
        )]))
        .await
        .unwrap();
    let added = name(&["added", "example"]);

    let response = server
        .handle(update([record(
            added.clone(),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 9)),
        )]))
        .await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(persistence.snapshots.lock().unwrap().is_empty());
    assert_not_published(
        &server,
        Question {
            qname: added,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        },
    )
    .await;
}

#[tokio::test]
async fn direct_signature_and_denial_proof_mutations_are_refused_without_persistence() {
    for rtype in [
        RecordType::RRSIG,
        RecordType::NSEC,
        RecordType::NSEC3,
        RecordType::NSEC3PARAM,
    ] {
        let persistence = Arc::new(MemoryPersistence::default());
        let server = server(Arc::clone(&persistence));
        server.install(zone_with([])).await.unwrap();

        let response = server
            .handle(update([delete_rrset(name(&["example"]), rtype)]))
            .await;

        assert_eq!(response.headers.rcode, RCode::Refused, "TYPE {rtype:?}");
        assert!(persistence.snapshots.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn dynamic_snapshots_reject_missing_glue_and_data_at_a_new_zone_cut() {
    let child = name(&["child", "example"]);
    let scenarios = [
        vec![record(
            child.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "child", "example"])),
        )],
        vec![
            record(
                child.clone(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 10)),
            ),
            record(
                child.clone(),
                RecordType::NS,
                RData::NS(name(&["ns", "elsewhere"])),
            ),
        ],
    ];

    for operations in scenarios {
        let persistence = Arc::new(MemoryPersistence::default());
        let server = server(Arc::clone(&persistence));
        server.install(zone_with([])).await.unwrap();

        let response = server.handle(update(operations)).await;

        assert_eq!(response.headers.rcode, RCode::ServerFailure);
        assert!(persistence.snapshots.lock().unwrap().is_empty());
        assert_not_published(
            &server,
            Question {
                qname: child.clone(),
                qtype: QueryType::NS,
                qclass: QClassType::Class(ClassType::IN),
            },
        )
        .await;
    }
}

#[tokio::test]
async fn dynamic_snapshots_reject_alias_and_addressless_authoritative_targets() {
    let mail = name(&["mail", "example"]);
    let apex = name(&["example"]);
    let scenarios = [
        vec![
            record(
                mail.clone(),
                RecordType::CNAME,
                RData::CNAME(name(&["www", "example"])),
            ),
            record(
                apex.clone(),
                RecordType::MX,
                RData::MX {
                    preference: 10,
                    exchange: mail.clone(),
                },
            ),
        ],
        vec![record(
            apex.clone(),
            RecordType::MX,
            RData::MX {
                preference: 10,
                exchange: mail,
            },
        )],
    ];

    for operations in scenarios {
        let persistence = Arc::new(MemoryPersistence::default());
        let server = server(Arc::clone(&persistence));
        server.install(zone_with([])).await.unwrap();

        let response = server.handle(update(operations)).await;

        assert_eq!(response.headers.rcode, RCode::ServerFailure);
        assert!(persistence.snapshots.lock().unwrap().is_empty());
        assert_not_published(
            &server,
            Question {
                qname: apex.clone(),
                qtype: QueryType::MX,
                qclass: QClassType::Class(ClassType::IN),
            },
        )
        .await;
    }
}

#[tokio::test]
async fn duplicate_additions_are_noops_and_new_members_inherit_the_rrset_ttl() {
    let persistence = Arc::new(MemoryPersistence::default());
    let server = server(Arc::clone(&persistence));
    let owner = name(&["multi", "example"]);
    let mut first = record(
        owner.clone(),
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 10)),
    );
    let mut second = record(
        owner.clone(),
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 11)),
    );
    first.ttl = 60;
    second.ttl = 60;
    server
        .install(zone_with([first.clone(), second]))
        .await
        .unwrap();

    first.ttl = 900;
    let duplicate = server.handle(update([first])).await;
    assert_eq!(duplicate.headers.rcode, RCode::Ok);
    assert!(persistence.snapshots.lock().unwrap().is_empty());

    let mut third = record(
        owner.clone(),
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 12)),
    );
    third.ttl = 1_200;
    let inserted = server.handle(update([third])).await;
    assert_eq!(inserted.headers.rcode, RCode::Ok);
    let mut singleton = record(
        name(&["singleton", "example"]),
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 20)),
    );
    singleton.ttl = 900;
    let singleton_added = server.handle(update([singleton])).await;
    assert_eq!(singleton_added.headers.rcode, RCode::Ok);

    let snapshots = persistence.snapshots.lock().unwrap();
    let insertion_snapshot = &snapshots[0];
    assert_eq!(
        insertion_snapshot
            .iter()
            .filter(|record| record.name.eq_dns(&owner) && record.rtype == RecordType::A)
            .map(|record| record.ttl)
            .collect::<Vec<_>>(),
        vec![60, 60, 60]
    );
    assert!(matches!(
        insertion_snapshot[0].rdata,
        RData::SOA { serial: 2, .. }
    ));
    assert_eq!(
        snapshots[1]
            .iter()
            .find(|record| record.name.eq_dns(&name(&["singleton", "example"])))
            .unwrap()
            .ttl,
        900
    );
}

#[tokio::test]
async fn dynamic_updates_never_publish_soa_serial_zero_at_wrap() {
    let persistence = Arc::new(MemoryPersistence::default());
    let server = server(Arc::clone(&persistence));
    server.install(zone_with_serial(u32::MAX)).await.unwrap();

    let explicit_zero = server.handle(update([soa(0)])).await;
    assert_eq!(explicit_zero.headers.rcode, RCode::Ok);
    assert!(persistence.snapshots.lock().unwrap().is_empty());

    let automatic_wrap = server
        .handle(update([record(
            name(&["added", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 20)),
        )]))
        .await;
    assert_eq!(automatic_wrap.headers.rcode, RCode::Ok);
    assert!(
        persistence.snapshots.lock().unwrap()[0]
            .iter()
            .any(|record| matches!(record.rdata, RData::SOA { serial: 1, .. }))
    );
}

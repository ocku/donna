use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use dns::master::MasterFile;
use dns::{
    ClassType, DomainName, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};

use super::*;

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn zone(serial: u32, address: Ipv4Addr) -> Zone {
    let apex = name(&["example"]);
    Zone::from_master(
        apex.clone(),
        MasterFile {
            records: vec![
                ResourceRecord {
                    name: apex.clone(),
                    rtype: RecordType::SOA,
                    class: ClassType::IN,
                    ttl: 300,
                    rdata: RData::SOA {
                        mname: name(&["primary", "invalid"]),
                        rname: DomainName::root(),
                        serial,
                        refresh: 60,
                        retry: 60,
                        expire: 3_600,
                        minimum: 300,
                    },
                },
                ResourceRecord {
                    name: apex.clone(),
                    rtype: RecordType::NS,
                    class: ClassType::IN,
                    ttl: 300,
                    rdata: RData::NS(DomainName::root()),
                },
                ResourceRecord {
                    name: name(&["www", "example"]),
                    rtype: RecordType::A,
                    class: ClassType::IN,
                    ttl: 300,
                    rdata: RData::A(address),
                },
            ],
        },
    )
    .unwrap()
}

async fn installed_address(server: &NameServer) -> Ipv4Addr {
    let response = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: name(&["www", "example"]),
                    qtype: QueryType::A,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap(),
        )
        .await;
    match response.answers.as_slice() {
        [
            ResourceRecord {
                rdata: RData::A(address),
                ..
            },
        ] => *address,
        answer => panic!("unexpected answer: {answer:?}"),
    }
}

#[tokio::test]
async fn changed_install_requires_a_strictly_newer_rfc1982_serial() {
    let server = NameServer::new();
    let original = Ipv4Addr::new(192, 0, 2, 1);
    assert_eq!(
        server.install(zone(100, original)).await.unwrap(),
        InstallOutcome::Installed
    );

    for rejected in [100, 99, 100_u32.wrapping_add(1 << 31)] {
        assert_eq!(
            server
                .install(zone(rejected, Ipv4Addr::new(192, 0, 2, 2)))
                .await
                .unwrap(),
            InstallOutcome::StaleSerial
        );
        assert_eq!(installed_address(&server).await, original);
    }

    let replacement = Ipv4Addr::new(192, 0, 2, 3);
    assert_eq!(
        server.install(zone(101, replacement)).await.unwrap(),
        InstallOutcome::Replaced
    );
    assert_eq!(installed_address(&server).await, replacement);

    assert_eq!(
        server.install(zone(101, replacement)).await.unwrap(),
        InstallOutcome::Unchanged
    );
}

#[tokio::test]
async fn aborting_an_install_waiter_does_not_cancel_the_owned_installation() {
    let server = NameServer::new();
    server
        .install(zone(1, Ipv4Addr::new(192, 0, 2, 1)))
        .await
        .unwrap();
    let mutation = server
        .zone_mutation_lock(&name(&["example"]), ClassType::IN)
        .await;
    let held = Arc::clone(&mutation).lock_owned().await;

    let installing = server.clone();
    let caller = tokio::spawn(async move {
        installing
            .install(zone(2, Ipv4Addr::new(192, 0, 2, 2)))
            .await
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&mutation) < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the server-owned installation task should acquire the mutation handle");
    caller.abort();
    drop(held);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if installed_address(&server).await == Ipv4Addr::new(192, 0, 2, 2) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the server-owned installation must finish after its caller is aborted");
}

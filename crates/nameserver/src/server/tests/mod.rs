use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU8,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use dns::master::MasterFile;
use dns::{
    ClassType, DomainName, FromWire, Headers, IntoWire, QClassType, QueryType, RData, RecordType,
    Sig0SigningKey, TsigAlgorithm, TsigAuthenticationError, TsigErrorCode, TsigKey,
    TsigStreamVerifier,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::Notify,
};
use transport::{
    TcpTransport, Transport, TransportError, TransportProtocol, TransportServer, UdpTransport,
};

use super::*;

mod notify_fixtures;
use notify_fixtures::*;

fn raw_query_with_question_codes(qtype: u16, qclass: u16) -> Vec<u8> {
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let mut packet = query.into_wire().unwrap();
    let question_codes = packet.len() - 4;
    packet[question_codes..question_codes + 2].copy_from_slice(&qtype.to_be_bytes());
    packet[question_codes + 2..].copy_from_slice(&qclass.to_be_bytes());
    packet
}

async fn raw_udp_exchange(address: SocketAddr, query: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let socket = avoid_udp_destination(socket, address);
    socket.connect(address).await.unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if socket.send(query).await.is_err() {
                tokio::task::yield_now().await;
                continue;
            }
            let mut response = vec![0; 512];
            match tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut response)).await
            {
                Ok(Ok(length)) => {
                    response.truncate(length);
                    return response;
                }
                Ok(Err(_)) | Err(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .unwrap()
}

fn avoid_udp_destination(socket: UdpSocket, address: SocketAddr) -> UdpSocket {
    if socket.local_addr().unwrap().port() == address.port() {
        // The server may not have bound its reserved port yet. Keep this
        // socket alive while choosing another port so we cannot send to self.
        // Bind synchronously so the server task cannot run while we hold its
        // destination port. Release it before registering the replacement.
        let replacement = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        drop(socket);
        replacement.set_nonblocking(true).unwrap();
        UdpSocket::from_std(replacement).unwrap()
    } else {
        socket
    }
}

#[tokio::test]
async fn raw_udp_client_cannot_bind_its_destination_port() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = socket.local_addr().unwrap();
    let socket = avoid_udp_destination(socket, destination);
    assert_ne!(socket.local_addr().unwrap().port(), destination.port());
    // The released destination remains available for the server.
    let server = UdpSocket::bind(destination).await.unwrap();
    socket.connect(destination).await.unwrap();
    socket.send(b"query").await.unwrap();
    let mut packet = [0; 5];
    let (length, _) = server.recv_from(&mut packet).await.unwrap();
    assert_eq!(&packet[..length], b"query");
}

async fn raw_tcp_exchange(address: SocketAddr, query: &[u8]) -> Vec<u8> {
    let mut stream = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match TcpStream::connect(address).await {
                Ok(stream) => return stream,
                Err(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .unwrap();
    stream.write_u16(query.len() as u16).await.unwrap();
    stream.write_all(query).await.unwrap();
    let length = usize::from(stream.read_u16().await.unwrap());
    let mut response = vec![0; length];
    stream.read_exact(&mut response).await.unwrap();
    response
}

fn test_tsig_key(name_label: &str) -> TsigKey {
    TsigKey::new(
        name(&[name_label]),
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap()
}

fn test_sig0_key() -> Sig0SigningKey {
    let pkcs8 =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    Sig0SigningKey::from_ed25519_pkcs8(name(&["host", "example"]), 0, 3, pkcs8.as_ref()).unwrap()
}

fn tsig_query(id: u16) -> Message {
    Message::builder()
        .headers(Headers {
            id,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

fn assert_header_only_formerr(packet: &[u8]) {
    let response = Message::from_wire(packet).unwrap();
    assert_eq!(response.headers.id, 42);
    assert!(response.headers.qr);
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(response.questions.is_empty());
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert!(response.additionals.is_empty());
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

fn class_record(
    name: DomainName,
    rtype: RecordType,
    class: ClassType,
    rdata: RData,
) -> ResourceRecord {
    class_record_with_ttl(name, rtype, class, 60, rdata)
}

fn class_record_with_ttl(
    name: DomainName,
    rtype: RecordType,
    class: ClassType,
    ttl: u32,
    rdata: RData,
) -> ResourceRecord {
    ResourceRecord {
        name,
        rtype,
        class,
        ttl,
        rdata,
    }
}

fn record(name: DomainName, rtype: RecordType, rdata: RData) -> ResourceRecord {
    record_with_ttl(name, rtype, 60, rdata)
}

fn record_with_ttl(name: DomainName, rtype: RecordType, ttl: u32, rdata: RData) -> ResourceRecord {
    class_record_with_ttl(name, rtype, ClassType::IN, ttl, rdata)
}

fn rrsig(owner: DomainName, covered: RecordType, labels: u8) -> ResourceRecord {
    record(
        owner,
        RecordType::RRSIG,
        RData::RRSIG(dns::Rrsig {
            type_covered: u16::from(covered),
            algorithm: 8,
            labels,
            original_ttl: 60,
            signature_expiration: u32::MAX,
            signature_inception: 0,
            key_tag: 1,
            signer_name: name(&["example"]),
            signature: vec![1],
        }),
    )
}

fn query_with_do(qname: DomainName, qtype: QueryType, dnssec_ok: bool) -> Message {
    let mut builder = Message::builder().questions([Question {
        qname,
        qtype,
        qclass: QClassType::Class(ClassType::IN),
    }]);
    if dnssec_ok {
        builder = builder.additionals([dns::Edns {
            dnssec_ok: true,
            ..dns::Edns::new(1232)
        }
        .into_record()]);
    }
    builder.build().unwrap()
}

fn update_meta(owner: DomainName, rtype: RecordType, class: u16) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype,
        class: ClassType::Unknown(class),
        ttl: 0,
        rdata: RData::Unknown(Vec::new()),
    }
}

fn update_request(
    prerequisites: impl IntoIterator<Item = ResourceRecord>,
    operations: impl IntoIterator<Item = ResourceRecord>,
) -> Message {
    Message::builder()
        .headers(Headers {
            id: 0x2136,
            opcode: OpCode::Update,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .answers(prerequisites)
        .authorities(operations)
        .build()
        .unwrap()
}

fn notify_request() -> Message {
    let zone = name(&["example"]);
    Message::builder()
        .headers(Headers {
            id: 0x1996,
            opcode: OpCode::Notify,
            aa: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: zone.clone(),
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .answers([record(
            zone,
            RecordType::SOA,
            RData::SOA {
                mname: name(&["primary", "invalid"]),
                rname: DomainName::root(),
                serial: 2,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 300,
            },
        )])
        .build()
        .unwrap()
}

fn test_zone_with_serial(serial: u32) -> Zone {
    let zone = test_zone();
    let mut records = zone.records().to_vec();
    for record in &mut records {
        if let RData::SOA {
            serial: current, ..
        } = &mut record.rdata
        {
            *current = serial;
        }
    }
    Zone::from_master(name(&["example"]), MasterFile { records }).unwrap()
}

fn update_server(persistence: Arc<MemoryUpdatePersistence>) -> NameServer {
    NameServer::with_config(NameServerConfig {
        update_persistence: Some(persistence),
        allow_insecure_updates: true,
        ..NameServerConfig::default()
    })
}

fn make_zone(
    apex: DomainName,
    class: ClassType,
    minimum: u32,
    mut records: Vec<ResourceRecord>,
) -> Zone {
    let mut zone_records = vec![
        class_record(
            apex.clone(),
            RecordType::SOA,
            class,
            RData::SOA {
                mname: name(&["primary", "invalid"]),
                rname: DomainName::root(),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum,
            },
        ),
        class_record(
            apex.clone(),
            RecordType::NS,
            class,
            RData::NS(DomainName::root()),
        ),
    ];
    zone_records.append(&mut records);
    Zone::from_master(
        apex,
        MasterFile {
            records: zone_records,
        },
    )
    .unwrap()
}

fn add_nsec3_chain(zone: Zone, opt_out: bool) -> Zone {
    let apex = zone.apex().clone();
    let class = zone.class();
    let mut records = zone.records().to_vec();
    let chain = dns::Nsec3Chain::build(
        &apex,
        class,
        &records,
        dns::Nsec3param {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
        },
        60,
        opt_out,
        0,
    )
    .unwrap();
    let (parameters, proofs) = chain.into_records();
    records.push(parameters);
    records.push(rrsig(apex.clone(), RecordType::SOA, 1));
    for proof in proofs {
        let owner = proof.name.clone();
        records.push(proof);
        records.push(rrsig(owner, RecordType::NSEC3, 2));
    }
    Zone::from_master(apex, MasterFile { records }).unwrap()
}

fn test_zone() -> Zone {
    test_zone_for_class(
        ClassType::IN,
        Some((RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 1)))),
    )
}

fn axfr_peer() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53))
}

fn axfr_server() -> NameServer {
    NameServer::with_config(NameServerConfig {
        allow_axfr_to: vec![
            (
                Ipv4Addr::new(192, 0, 2, 0).into(),
                Ipv4Addr::new(255, 255, 255, 0).into(),
            ),
            (
                Ipv4Addr::LOCALHOST.into(),
                Ipv4Addr::new(255, 255, 255, 255).into(),
            ),
        ],
        ..NameServerConfig::default()
    })
}

fn test_zone_for_class(class: ClassType, www_record: Option<(RecordType, RData)>) -> Zone {
    let mut records = vec![class_record(
        name(&["alias", "example"]),
        RecordType::CNAME,
        class,
        RData::CNAME(name(&["target", "other"])),
    )];
    if let Some((rtype, rdata)) = www_record {
        records.push(class_record(name(&["www", "example"]), rtype, class, rdata));
    }
    make_zone(name(&["example"]), class, 300, records)
}

mod additional_records;
mod binary_zone_keys;
mod borrowed_negative;
mod cname_wire;
mod delegation_auth_transport;
mod dname;
mod dnssec;
mod ds;
mod immediate;
mod incremental_transfer_edns;
mod notify;
mod prepared_negative;
mod prepared_wildcard;
mod request_validation;
mod resolution;
mod sig0;
mod single_zone_index;
mod transaction_auth;
mod transfers_resolution;
mod updates;

mod borrowed_positive;

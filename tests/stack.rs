//! Public API embedding regression; shipped daemon workflows live in cli.rs.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use dns::master::MasterFile;
use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RCode, RData,
    RecordType,
};
use nameserver::{NameServer, NameServerConfig, Zone};
use resolver::{Resolver, ResolverConfig};
use transport::{TcpTransport, Transport, TransportServer, UdpTransport};

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn query(qname: DomainName, qtype: QueryType) -> Message {
    Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname,
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

async fn server(axfr: bool) -> NameServer {
    let apex = name(&["example"]);
    let master = MasterFile::parse(
        concat!(
            "$TTL 60\n",
            "@ IN SOA ns.example. hostmaster.example. 1 60 60 60 30\n",
            "@ IN NS ns.example.\n",
            "ns IN A 127.0.0.1\n",
            "www IN A 192.0.2.1\n",
        ),
        Some(apex.clone()),
    )
    .unwrap();

    let config = NameServerConfig {
        allow_axfr_to: axfr
            .then_some((
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            ))
            .into_iter()
            .collect(),
        ..NameServerConfig::default()
    };

    let server = NameServer::with_config(config);
    server
        .install(Zone::from_master(apex, master).unwrap())
        .await
        .unwrap();

    server
}

fn unused_udp_address() -> SocketAddr {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();

    socket.local_addr().unwrap()
}

fn unused_tcp_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();

    listener.local_addr().unwrap()
}

#[tokio::test]
async fn authoritative_server_works_over_udp_tcp_resolver_cache_and_axfr() {
    let udp_address = unused_udp_address();
    let tcp_address = unused_tcp_address();
    let udp_server = tokio::spawn(UdpTransport.serve(udp_address, server(false).await));
    let tcp_server = tokio::spawn(TcpTransport.serve(tcp_address, server(true).await));

    tokio::time::sleep(Duration::from_millis(10)).await;

    let missing = UdpTransport
        .exchange(
            udp_address,
            &query(name(&["missing", "example"]), QueryType::A),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert!(missing.headers.aa);
    assert_eq!(missing.headers.rcode, RCode::NameError);
    assert!(matches!(missing.authorities.as_slice(), [record]
        if record.rtype == RecordType::SOA && record.ttl == 30));

    let question = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    let resolver = Resolver::new(
        UdpTransport,
        ResolverConfig {
            root_servers: vec![udp_address],
            timeout: Duration::from_secs(1),
            ..ResolverConfig::default()
        },
    );

    let resolved = resolver.resolve(question.clone()).await.unwrap();

    assert!(matches!(resolved.answers.as_slice(), [record]
        if matches!(record.rdata, RData::A(address) if address == Ipv4Addr::new(192, 0, 2, 1))));

    udp_server.abort();

    assert_eq!(resolver.resolve(question).await.unwrap().answers.len(), 1);

    let tcp_answer = TcpTransport
        .exchange(
            tcp_address,
            &query(name(&["www", "example"]), QueryType::A),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert!(tcp_answer.headers.aa);
    assert_eq!(tcp_answer.answers.len(), 1);

    let transfer = TcpTransport
        .transfer(
            tcp_address,
            &query(name(&["example"]), QueryType::AXFR),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    tcp_server.abort();

    assert_eq!(transfer.first().unwrap().rtype, RecordType::SOA);
    assert_eq!(transfer.last().unwrap().rtype, RecordType::SOA);
    assert!(transfer.first().unwrap().eq_dns(transfer.last().unwrap()));
    assert!(
        transfer
            .iter()
            .any(|record| record.name.eq_dns(&name(&["www", "example"])))
    );
}

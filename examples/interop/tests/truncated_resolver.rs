//! Exercise automatic iterative resolution, including classic DNS fallback.
use std::{net::Ipv4Addr, time::Duration};

use dns::{
    ClassType, DomainName, FromWire, Headers, IntoWire, Message, QClassType, QueryType, Question,
    RCode, RData, RecordType, ResourceRecord,
};
use resolver::{Resolver, ResolverConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use transport::UdpTransport;

const PARTIAL: &[u8] =
    include_bytes!("../../../crates/transport/src/udp/tests/fixtures/hickory-0.26.3-many-a-tc.bin");

#[tokio::test]
async fn iterative_resolver_automatically_retries_partial_classic_udp_over_tcp() {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(address).await.unwrap();
    let authority = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
        let extended = Message::from_wire(&buffer[..length]).unwrap();
        assert!(extended.edns().unwrap().is_some());
        let error = Message::builder()
            .headers(Headers {
                id: extended.headers.id,
                qr: true,
                rd: extended.headers.rd,
                rcode: RCode::FormatError,
                ..Headers::default()
            })
            .questions(extended.questions)
            .build()
            .unwrap()
            .into_wire()
            .unwrap();
        udp.send_to(&error, peer).await.unwrap();
        let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
        let classic = Message::from_wire(&buffer[..length]).unwrap();
        assert!(classic.edns().unwrap().is_none());
        let mut partial = PARTIAL.to_vec();
        partial[..2].copy_from_slice(&classic.headers.id.to_be_bytes());
        partial[2] = (partial[2] & !1) | u8::from(classic.headers.rd);
        assert!(Message::from_wire(&partial).is_err());
        udp.send_to(&partial, peer).await.unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut buffer = vec![0; usize::from(length)];
        stream.read_exact(&mut buffer).await.unwrap();
        let query = Message::from_wire(&buffer).unwrap();
        let response = Message::builder()
            .headers(Headers {
                id: query.headers.id,
                qr: true,
                aa: true,
                rd: query.headers.rd,
                ..Headers::default()
            })
            .questions(query.questions.clone())
            .answers((1..=96).map(|last| ResourceRecord {
                name: query.questions[0].qname.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, last)),
            }))
            .build()
            .unwrap()
            .into_wire()
            .unwrap();
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let resolver = Resolver::new(
        UdpTransport,
        ResolverConfig {
            root_servers: vec![address],
            timeout: Duration::from_millis(500),
            max_steps: 8,
            max_attempts_per_server: 2,
            cache_capacity: 0,
            ..ResolverConfig::default()
        },
    );
    let question = Question {
        qname: DomainName::from_dotted("many.example.test.").unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        resolver.resolve_with_stats(question),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(outcome.response().headers.rcode, RCode::Ok);
    assert_eq!(outcome.response().answers.len(), 96);
    for last in 1..=96 {
        assert!(
            outcome
                .response()
                .answers
                .iter()
                .any(|rr| { rr.rdata == RData::A(Ipv4Addr::new(192, 0, 2, last)) })
        );
    }
    assert_eq!(outcome.stats().udp_transmissions(), 2);
    assert_eq!(outcome.stats().edns_fallbacks(), 1);
    assert_eq!(outcome.stats().tcp_transitions(), 1);
    assert_eq!(outcome.stats().tcp_completions(), 1);
    assert_eq!(outcome.stats().timeouts(), 0);
    authority.await.unwrap();
}

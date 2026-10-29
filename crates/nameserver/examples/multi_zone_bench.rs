//! Scoped release-mode profiling of authoritative routing and response assembly.
//! Run `cargo run --release -p nameserver --example multi_zone_bench`.
use std::{hint::black_box, time::Instant};

use dns::{
    ClassType, DomainName, IntoWire, Message, QClassType, QueryType, Question, master::MasterFile,
};
use nameserver::{NameServer, Zone};
use transport::{DnsRequestHandler, TransportProtocol};

fn main() {
    let iterations = std::env::var("MULTI_ZONE_ITERATIONS")
        .unwrap_or_else(|_| "500000".into())
        .parse::<usize>()
        .unwrap();
    assert!(iterations > 0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let server = NameServer::new();
    runtime.block_on(async {
        for apex in ["example.test.", "child.example.test.", "other.test."] {
            let text = format!("$ORIGIN {apex}\n$TTL 300\n@ IN SOA ns hostmaster 1 3600 600 86400 300\n@ IN NS ns\nwww IN A 192.0.2.1\n");
            let name = DomainName::from_dotted(apex).unwrap();
            let zone = Zone::from_master(name.clone(), MasterFile::parse(&text, Some(name)).unwrap()).unwrap();
            server.install(zone).await.unwrap();
        }
    });
    let peer = "127.0.0.1:1234".parse().unwrap();
    println!("repeat,workload,ns_per_query");
    for (workload, qname, qtype) in [
        ("nested-positive", "www.child.example.test.", QueryType::A),
        ("parent-positive", "www.example.test.", QueryType::A),
        ("nested-ds", "child.example.test.", QueryType::DS),
        ("out-of-zone", "www.unhosted.test.", QueryType::A),
    ] {
        let query = Message::builder()
            .questions([Question {
                qname: DomainName::from_dotted(qname).unwrap(),
                qtype,
                qclass: QClassType::Class(ClassType::IN),
            }])
            .build()
            .unwrap();
        let wire = query.into_wire().unwrap();
        let execute = || {
            server
                .try_handle(black_box(&query), &wire, peer, TransportProtocol::Udp)
                .unwrap()
        };
        black_box(execute());
        for repeat in 0..5 {
            let start = Instant::now();
            for _ in 0..iterations {
                black_box(execute());
            }
            println!(
                "{repeat},{workload},{}",
                start.elapsed().as_nanos() / iterations as u128
            );
        }
    }
}

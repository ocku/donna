//! Private actual prepare_packet component; no production API is retained.
use dns::{
    ClassType, DomainName, Edns, IntoWire, Message, QClassType, QueryType, Question,
    master::MasterFile,
};
use nameserver::{NameServer, Zone};
use std::{hint::black_box, net::SocketAddr, sync::Arc, time::Instant};
use tokio::{
    net::UdpSocket,
    sync::{Barrier, Semaphore},
};
use transport::{UdpPrepareProfileBatch, udp_profile_prepare, udp_profile_response};

const OPS: usize = 65536;

fn main() {
    for workers in [1, 2] {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let server = Arc::new(NameServer::new());
            let apex = DomainName::from_dotted("example.test.").unwrap();
            let zone = MasterFile::parse(include_str!("../../fixtures/basic/zone.db"), Some(apex.clone())).unwrap();
            server.install(Zone::from_master(apex, zone).unwrap()).await.unwrap();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let permits = Arc::new(Semaphore::new(256));
            let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();
            for (case, owner, qtype) in [
                ("positive", "www.example.test.", QueryType::A),
                ("wildcard", "m.wild.example.test.", QueryType::TXT),
            ] {
                let query = Message::builder().questions([Question {
                    qname: DomainName::from_dotted(owner).unwrap(), qtype,
                    qclass: QClassType::Class(ClassType::IN),
                }]).additionals([Edns::new(1232).into_record()]).build().unwrap();
                let wire = Arc::new(query.into_wire().unwrap());
                let expected = Arc::new(server.handle(query).await.into_wire().unwrap());
                assert_eq!(udp_profile_response(server.as_ref(), peer, &wire), *expected);
                for phase in ["response", "prepare"] {
                    for sample in 0..3 {
                        let barrier = Arc::new(Barrier::new(workers + 1));
                        let mut tasks = Vec::new();
                        for worker in 0..workers {
                            let (server, socket, permits, wire, expected, barrier) =
                                (server.clone(), socket.clone(), permits.clone(), wire.clone(), expected.clone(), barrier.clone());
                            tasks.push(tokio::spawn(async move {
                                let mut storage = UdpPrepareProfileBatch::default();
                                for _ in 0..8 { udp_profile_prepare(&socket, &server, peer, &wire, &permits,
                                    &mut storage, &expected, true).await; }
                                barrier.wait().await;
                                let started = Instant::now();
                                let mut checksum = 0;
                                for batch in 0..OPS / 16 {
                                    let verify = batch % 64 == 0;
                                    if phase == "prepare" {
                                        checksum += black_box(udp_profile_prepare(black_box(&socket), black_box(&server),
                                            peer, black_box(&wire), &permits, &mut storage, &expected, verify).await);
                                    } else {
                                        for _ in 0..16 {
                                            let reply = udp_profile_response(black_box(server.as_ref()), peer, black_box(&wire));
                                            if verify { assert_eq!(reply, *expected); }
                                            checksum += black_box(reply).len();
                                        }
                                    }
                                }
                                let elapsed = started.elapsed().as_nanos();
                                assert_eq!(checksum, OPS * expected.len());
                                (worker, elapsed)
                            }));
                        }
                        barrier.wait().await;
                        for task in tasks {
                            let (worker, elapsed) = task.await.unwrap();
                            println!("{{\"workers\":{workers},\"worker\":{worker},\"case\":\"{case}\",\"phase\":\"{phase}\",\"sample\":{sample},\"operations\":{OPS},\"elapsed_ns\":{elapsed},\"ns_per_operation\":{}}}", elapsed as f64 / OPS as f64);
                        }
                        assert_eq!(permits.available_permits(), 256);
                    }
                }
            }
        });
    }
}

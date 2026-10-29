//! Independently authored EDNS packets exercise role and ACL error paths.

use super::support::*;
use dns::{Edns, FromWire, Message};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_secs(1);
const QUESTION: &[u8] = b"\x07outside\x04test\0\0\x01\0\x01";

struct Case {
    name: &'static str,
    wire: Vec<u8>,
    rcode: u16,
    dnssec_ok: Option<bool>,
}

fn opt(version: u8, dnssec_ok: bool, extended_rcode: u8, options: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0];
    for value in [41_u16, 1232] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    let flags = u32::from(extended_rcode) << 24
        | u32::from(version) << 16
        | if dnssec_ok { 0x8000 } else { 0 };
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&(options.len() as u16).to_be_bytes());
    bytes.extend_from_slice(options);
    bytes
}

fn request(records: &[Vec<u8>], misplaced: bool) -> Vec<u8> {
    let count = records.len() as u16;
    let counts = if misplaced {
        [1, count, 0, 0]
    } else {
        [1, 0, 0, count]
    };
    let mut bytes: Vec<_> = [0x4d52, 0x0110] // ID, RD/CD set.
        .into_iter()
        .chain(counts)
        .flat_map(u16::to_be_bytes)
        .collect();
    bytes.extend_from_slice(QUESTION);
    bytes.extend(records.iter().flatten());
    bytes
}

fn cases() -> Vec<Case> {
    let plain = opt(0, true, 0, &[]);
    let mut named = plain.clone();
    named.splice(..1, b"\x03bad\0".iter().copied());
    let mut future_flags = plain.clone();
    future_flags[7..9].copy_from_slice(&0x8123_u16.to_be_bytes());

    let mut cases = vec![Case {
        name: "classic-refusal",
        wire: request(&[], false),
        rcode: 5,
        dnssec_ok: None,
    }];
    for (name, records, misplaced, rcode, dnssec_ok) in [
        ("edns-refusal", vec![plain.clone()], false, 5, true),
        ("do-clear", vec![opt(0, false, 0, &[])], false, 5, false),
        ("badvers", vec![opt(1, true, 0, &[])], false, 16, true),
        (
            "badvers-extended-rcode",
            vec![opt(1, true, 1, &[])],
            false,
            16,
            true,
        ),
        (
            "duplicate-opt",
            vec![plain.clone(), plain.clone()],
            false,
            1,
            false,
        ),
        ("misplaced-opt", vec![plain], true, 1, false),
        ("named-opt", vec![named], false, 1, false),
        (
            "request-extended-rcode",
            vec![opt(0, true, 1, &[])],
            false,
            1,
            true,
        ),
        (
            "unknown-option",
            vec![opt(0, true, 0, &[0xfd, 0xe8, 0, 1, 7])],
            false,
            5,
            true,
        ),
        ("future-flags", vec![future_flags], false, 5, true),
        (
            "invalid-ede",
            vec![opt(0, true, 0, &[0, 15, 0, 1, 0])],
            false,
            1,
            true,
        ),
        (
            "badvers-invalid-ede",
            vec![opt(1, true, 0, &[0, 15, 0, 1, 0])],
            false,
            1,
            true,
        ),
    ] {
        cases.push(Case {
            name,
            wire: request(&records, misplaced),
            rcode,
            dnssec_ok: Some(dnssec_ok),
        });
    }
    cases
}

fn exchange(address: SocketAddr, protocol: &str, query: &[u8]) -> Vec<u8> {
    if protocol == "udp" {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        socket.connect(address).unwrap();
        socket.send(query).unwrap();
        let mut response = vec![0; u16::MAX as usize];
        let length = socket.recv(&mut response).unwrap();
        response.truncate(length);
        return response;
    }
    let mut socket = TcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap();
    socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    socket
        .write_all(&(query.len() as u16).to_be_bytes())
        .unwrap();
    socket.write_all(query).unwrap();
    let mut length = [0; 2];
    socket.read_exact(&mut length).unwrap();
    let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
    socket.read_exact(&mut response).unwrap();
    response
}

#[test]
fn edns_errors_keep_required_metadata_before_recursion_acl_refusal() {
    let upstream_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream_tcp.local_addr().unwrap();
    let upstream_udp = UdpSocket::bind(upstream_address).unwrap();
    upstream_tcp.set_nonblocking(true).unwrap();
    upstream_udp.set_nonblocking(true).unwrap();

    for role in ["recursive", "forward"] {
        for denied in [false, true] {
            for deferred in [false, true] {
                let mut daemon = Fixture::new();
                let mut config = format!(
                    "role='{role}'\nlog_queries={deferred}\n{}\n[access]\nrecursion={}\n[resolver]\nvalidate=false\nroot_servers=['{upstream_address}']\n",
                    daemon.listeners(),
                    if denied { "[]" } else { "['127.0.0.0/8']" }
                );
                if role == "forward" {
                    config += &format!("[[upstream]]\naddress='{upstream_address}'\n");
                }
                daemon.start(&config);
                let address = ([127, 0, 0, 1], daemon.port).into();
                for case in cases() {
                    if !denied && case.rcode == 5 {
                        continue; // Ordinary admitted queries require real resolution.
                    }
                    for protocol in ["udp", "tcp"] {
                        let wire = exchange(address, protocol, &case.wire);
                        let response = Message::from_wire(&wire).unwrap();
                        assert_eq!(
                            response.extended_rcode(),
                            case.rcode,
                            "{role} {protocol} {} denied={denied} deferred={deferred}",
                            case.name
                        );
                        assert_eq!(response.headers.id, 0x4d52);
                        assert_eq!(response.questions.len(), 1);
                        assert_eq!(
                            response.questions[0].qname,
                            dns::DomainName::from_dotted("outside.test.").unwrap()
                        );
                        assert_eq!(response.questions[0].qtype, dns::QueryType::A);
                        assert_eq!(
                            response.questions[0].qclass,
                            dns::QClassType::Class(dns::ClassType::IN)
                        );
                        assert!(response.headers.qr && response.headers.rd && response.headers.cd);
                        assert_eq!(response.headers.ra, !denied);
                        assert!(
                            !response.headers.aa && !response.headers.ad && !response.headers.tc
                        );
                        assert!(response.answers.is_empty() && response.authorities.is_empty());
                        let edns = response.edns().unwrap();
                        assert_eq!(edns.as_ref().map(|value| value.dnssec_ok), case.dnssec_ok);
                        assert_eq!(
                            u16::from_be_bytes([wire[10], wire[11]]),
                            u16::from(edns.is_some())
                        );
                        if let Some(edns) = edns {
                            assert_eq!(edns.version, Edns::VERSION);
                            assert_eq!(edns.z, 0);
                            assert!(edns.options.is_empty());
                        }
                        assert!(daemon.child.as_mut().unwrap().try_wait().unwrap().is_none());
                    }
                }
                daemon.stop();
            }
        }
    }
    assert_eq!(
        upstream_udp.recv_from(&mut [0; 512]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        upstream_tcp.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

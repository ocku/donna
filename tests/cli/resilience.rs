//! Malformed network input must not take down the shipped daemon.

use super::support::*;
use dns::{ClassType, DomainName, IntoWire, Message, QClassType, QueryType, Question};
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

const DNS_HEADER_OCTETS: usize = 12;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(1);

fn valid_request() -> Vec<u8> {
    Message::builder()
        .questions([Question {
            qname: DomainName::from_dotted("www.example.test.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
        .into_wire()
        .unwrap()
}

fn malformed_packets() -> Vec<Vec<u8>> {
    let valid = valid_request();
    let mut packets: Vec<_> = (0..valid.len())
        .map(|length| valid[..length].to_vec())
        .collect();

    for count_offset in [4, 6, 8, 10] {
        let mut packet = valid.clone();
        packet[count_offset..count_offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        packets.push(packet);
    }

    for encoded_name in [
        vec![0xc0, 0x0c],             // Pointer refers to itself.
        vec![0xc0, 0xff],             // Pointer lies outside the message.
        vec![0xc0, 0x0e, 0xc0, 0x0c], // Two pointers form a cycle.
        vec![0x40, 0],                // Reserved label type.
        vec![0x80, 0],                // Reserved label type.
        vec![63, b'x'],               // Label extends beyond the message.
    ] {
        let mut packet = valid[..DNS_HEADER_OCTETS].to_vec();
        packet.extend_from_slice(&encoded_name);
        packets.push(packet);
    }

    let mut bad_rdata = valid;
    bad_rdata[10..12].copy_from_slice(&1u16.to_be_bytes()); // One additional RR.
    bad_rdata.extend_from_slice(&[
        0, // Root owner.
        0, 41, // OPT record.
        4, 208, // Advertised payload size.
        0, 0, 0, 0, // TTL / EDNS flags.
        255, 255, // RDLENGTH exceeds remaining message.
    ]);
    packets.push(bad_rdata);

    packets
}

fn send_tcp_frame(address: SocketAddr, frame: &[u8]) {
    let mut tcp = TcpStream::connect_timeout(&address, CLIENT_TIMEOUT).unwrap();
    tcp.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    tcp.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    tcp.write_all(frame).unwrap();
    tcp.shutdown(Shutdown::Write).unwrap();

    // Wait for the server to finish this connection before inspecting logs.
    // Both EOF and a reset are legitimate rejection outcomes.
    if let Err(error) = tcp.read_to_end(&mut Vec::new()) {
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{error}");
    }
}

fn exercise_malformed_ingress(verbose: bool) -> String {
    let mut fixture = Fixture::new();
    fixture.write("zone.db", &zone("192.0.2.86", 1));
    fixture.start_with_verbosity(&authority(&fixture), verbose);

    let address = (Ipv4Addr::LOCALHOST, fixture.port);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();

    for packet in malformed_packets() {
        udp.send_to(&packet, address).unwrap();

        let mut frame = (packet.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&packet);
        send_tcp_frame(address.into(), &frame);
    }

    // Incomplete TCP frames must also release their connection on EOF.
    for frame in [&[0xff][..], &[0xff, 0xff, 0][..]] {
        send_tcp_frame(address.into(), frame);
    }

    for protocol in ["udp", "tcp", "udp", "tcp"] {
        assert_eq!(
            fixture.query("www.example.test", protocol)["answers"][0]["data"],
            "192.0.2.86",
            "healthy {protocol} query after malformed ingress"
        );
        assert!(
            fixture
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
    }

    fixture.stop();
    fixture.stderr()
}

#[test]
fn malformed_udp_and_tcp_packets_leave_daemon_alive_without_warning_spam() {
    let stderr = exercise_malformed_ingress(false);

    assert!(!stderr.contains("WARN"), "{stderr}");
    assert!(!stderr.contains("failed to decode DNS message"), "{stderr}");
}

#[test]
fn verbose_diagnostics_still_report_rejected_packets() {
    let stderr = exercise_malformed_ingress(true);

    assert!(stderr.contains("failed to decode DNS message"), "{stderr}");
}

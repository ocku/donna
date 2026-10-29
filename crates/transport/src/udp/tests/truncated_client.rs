use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

// Captured from pinned Hickory 0.26.3 image b40d16e1b92f...; the counted
// records end at offset500, followed by six octets of an incomplete owner.
const HICKORY_TC: &[u8] = include_bytes!("fixtures/hickory-0.26.3-many-a-tc.bin");

fn request() -> Message {
    Message::builder()
        .headers(Headers {
            id: 0x2000,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted("many.example.test.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

#[test]
fn real_hickory_partial_body_yields_only_a_correlatable_tc_marker() {
    assert_eq!(HICKORY_TC.len(), 506);
    assert!(Message::from_wire(HICKORY_TC).is_err());
    let response = Message::truncated_response_from_wire(HICKORY_TC).unwrap();
    assert!(response.headers.tc);
    assert!(response.headers.aa);
    assert!(matches_query(&response, &request()));
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert!(response.additionals.is_empty());
    for length in 35..=HICKORY_TC.len() {
        let marker = Message::truncated_response_from_wire(&HICKORY_TC[..length]).unwrap();
        assert!(matches_query(&marker, &request()));
        assert!(marker.answers.is_empty());
    }
    // The complete-message decoder remains strict for the same wire.
    let mut untruncated = HICKORY_TC.to_vec();
    untruncated[2] &= !2;
    assert!(Message::from_wire(&untruncated).is_err());
    assert!(Message::truncated_response_from_wire(&untruncated).is_err());
}

#[test]
fn truncated_response_requires_complete_valid_questions_and_header() {
    for length in 0..35 {
        assert!(Message::truncated_response_from_wire(&HICKORY_TC[..length]).is_err());
    }
    for mutation in 0..7 {
        let mut wire = HICKORY_TC.to_vec();
        match mutation {
            0 => wire[2] &= !0x80, // QR clear.
            1 => wire[3] |= 0x40,  // Reserved Z bit.
            2 => wire[4..6].copy_from_slice(&u16::MAX.to_be_bytes()),
            3 => wire[12..14].copy_from_slice(&[0xc0, 12]), // Self pointer.
            4 => wire[12..14].copy_from_slice(&[0xc0, 35]), // Forward body pointer.
            5 => wire[12] = 0x40,                           // Unsupported label encoding.
            _ => wire.resize(65536, 0),
        }
        assert!(
            Message::truncated_response_from_wire(&wire).is_err(),
            "mutation{mutation}"
        );
    }
}

#[test]
fn truncated_question_decoder_keeps_binary_root_and_backward_compression() {
    for qname in [
        DomainName::root(),
        DomainName::from_labels(vec![vec![0, 0xc0, 255], b"EXAMPLE".to_vec()]).unwrap(),
    ] {
        let mut query = request();
        query.questions[0].qname = qname;
        query.questions.push(query.questions[0].clone());
        let mut wire = query.into_wire().unwrap();
        wire[2] |= 0x82;
        // The second question may point backward into the first question.
        wire[6..12].fill(255);
        wire.extend_from_slice(&[0xc0, 0xff, 0, 1]);
        let response = Message::truncated_response_from_wire(&wire).unwrap();
        assert!(matches_query(&response, &query));
        assert_eq!(
            response.questions[0].qname.as_ref(),
            query.questions[0].qname.as_ref()
        );
    }
}

#[tokio::test]
async fn udp_tc_ignores_wrong_peer_id_opcode_question_and_oversize_packets() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut incoming = [0; 512];
        let (_, peer) = socket.recv_from(&mut incoming).await.unwrap();
        let rogue = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut spoof = HICKORY_TC.to_vec();
        spoof[2] &= !4; // distinguish a wrongly accepted rogue packet.
        rogue.send_to(&spoof, peer).await.unwrap();
        for mutation in 0..10 {
            let mut wire = HICKORY_TC.to_vec();
            match mutation {
                0 => wire[1] ^= 1,
                1 => wire[2] |= 0x10, // STATUS response, different opcode.
                2 => wire[13] = b'x',
                3 => wire[32] = 28,
                4 => wire[34] = 3,
                5 => wire[4..6].fill(0),
                6 => wire.truncate(34),
                7 => wire[12..14].copy_from_slice(&[0xc0, 12]),
                8 => wire[3] |= 0x40,
                _ => wire.resize(513, 0),
            }
            socket.send_to(&wire, peer).await.unwrap();
        }
        socket.send_to(HICKORY_TC, peer).await.unwrap();
    });
    let mut query = request();
    query.questions[0].qname = DomainName::from_dotted("MANY.Example.TEST.").unwrap();
    let response = UdpTransport
        .exchange(address, &query, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(response.headers.tc);
    assert!(response.headers.aa);
    assert!(matches_query(&response, &query));
    assert!(response.answers.is_empty());
    server.await.unwrap();
}

#[tokio::test]
async fn real_hickory_tc_packet_transitions_to_tcp_and_returns_the_full_rrset() {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(address).await.unwrap();
    let server = tokio::spawn(async move {
        let mut incoming = [0; 512];
        let (_, peer) = udp.recv_from(&mut incoming).await.unwrap();
        udp.send_to(HICKORY_TC, peer).await.unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut bytes = vec![0; usize::from(length)];
        stream.read_exact(&mut bytes).await.unwrap();
        let query = Message::from_wire(&bytes).unwrap();
        let response = Message::builder()
            .headers(Headers {
                id: query.headers.id,
                qr: true,
                aa: true,
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
    let query = request();
    let reply = UdpTransport
        .exchange(address, &query, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(reply.headers.tc);
    let response = UdpTransport
        .transition(TransitionReason::TruncatedResponse)
        .unwrap()
        .exchange(address, &query, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(!response.headers.tc);
    assert_eq!(response.answers.len(), 96);
    server.await.unwrap();
}

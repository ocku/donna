use super::*;

#[tokio::test]
async fn preserves_signed_questionless_update_responses() {
    for case in crate::tests::signed_responses::SignedResponse::cases(42) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(serve_socket(socket, case.handler()));
        let response = UdpTransport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.abort();
    }
}

#[tokio::test]
async fn preserves_inverse_response_discovered_questions() {
    for case in crate::tests::signed_responses::SignedResponse::inverse_cases(42) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(serve_socket(socket, case.handler()));
        let response = UdpTransport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.abort();
    }
}

struct OriginalWireHandler {
    expected: Vec<u8>,
}

impl DnsRequestHandler for OriginalWireHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            assert_eq!(request.wire_message(), self.expected);
            // Authentication must see the received representation, even when the
            // ordinary encoder would compress the same semantic message differently.
            assert_ne!(request.message().into_wire().unwrap(), self.expected);
            let mut response = request.message().clone();
            response.headers.qr = true;
            response.additionals.clear();
            assert!(request.respond(response));
        })
    }
}

#[tokio::test]
async fn preserves_the_received_udp_wire_representation_for_authentication() {
    let name = DomainName::from_dotted("WWW.Example.Test.").unwrap();
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: name.clone(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([ResourceRecord {
            name: name.clone(),
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 300,
            rdata: RData::TXT(vec![b"fixture".to_vec()]),
        }])
        .build()
        .unwrap();
    let mut packet = query.into_wire().unwrap();
    let additional_start = 12 + name.wire_len() + 4;
    assert_eq!(&packet[additional_start..additional_start + 2], &[0xc0, 12]);
    packet.splice(
        additional_start..additional_start + 2,
        name.into_wire().unwrap(),
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(serve_socket(
        socket,
        OriginalWireHandler {
            expected: packet.clone(),
        },
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(address).await.unwrap();
    client.send(&packet).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), receive_udp_message(&client))
        .await
        .unwrap();
    assert_eq!(response.headers.id, 42);
    assert!(response.headers.qr);
    assert!(crate::same_questions(&response.questions, &query.questions));
    task.abort();
}

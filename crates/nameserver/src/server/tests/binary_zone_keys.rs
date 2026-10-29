use super::*;
use transport::{DnsRequestHandler, ImmediateUdpResponse};

#[tokio::test]
async fn decoded_questions_keep_binary_and_maximum_length_zone_keys() {
    let apex = name(&["example"]);
    let labels = [
        vec![vec![0, b'.', 0x80, 0xff, b'A'], b"example".to_vec()],
        vec![
            vec![b'A'; 63],
            vec![b'B'; 63],
            vec![b'C'; 63],
            vec![b'D'; 53],
            b"example".to_vec(),
        ],
    ];
    let server = NameServer::new();
    let records = labels
        .iter()
        .map(|labels| {
            record(
                DomainName::from_labels(labels.clone()).unwrap(),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 89)),
            )
        })
        .collect();
    server
        .install(make_zone(apex, ClassType::IN, 30, records))
        .await
        .unwrap();
    for labels in labels {
        for folded in [false, true] {
            let labels: Vec<_> = labels
                .iter()
                .map(|v| {
                    if folded {
                        v.to_ascii_lowercase()
                    } else {
                        v.clone()
                    }
                })
                .collect();
            let query = query_with_do(
                DomainName::from_labels(labels).unwrap(),
                QueryType::A,
                false,
            );
            let wire = query.into_wire().unwrap();
            let decoded = Message::from_wire(&wire).unwrap();
            let response = match server
                .try_handle_udp(&decoded, &[], (Ipv4Addr::LOCALHOST, 1234).into(), 1232)
                .unwrap()
            {
                ImmediateUdpResponse::Encoded(reply) => {
                    assert!(reply.matches_request(&decoded));
                    reply.into_bytes()
                }
                ImmediateUdpResponse::Message(reply) => reply.into_wire().unwrap(),
            };
            let reply = Message::from_wire(&response).unwrap();
            assert_eq!(reply.answers.len(), 1);
            assert_eq!(
                reply.answers[0].rdata,
                RData::A(Ipv4Addr::new(192, 0, 2, 89))
            );
        }
    }
}

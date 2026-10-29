use super::*;

#[tokio::test]
async fn malformed_edns_keeps_formerr_and_connection_usable_without_padding() {
    let (server, task) = one_connection_server(|request: Message| async move {
        let valid_options = request
            .edns()
            .is_ok_and(|edns| edns.is_none_or(|edns| edns.validate_options().is_ok()));
        let mut edns = dns::Edns::default();
        edns.options.push(dns::EdnsOption::padding(16));
        Message {
            headers: Headers {
                qr: true,
                rcode: if !valid_options {
                    dns::RCode::FormatError
                } else {
                    dns::RCode::Ok
                },
                ..Headers::default()
            },
            questions: request.questions,
            answers: vec![],
            authorities: vec![],
            additionals: vec![edns.into_record()],
        }
    })
    .await;
    let config = client_config("localhost");
    let tcp = TcpStream::connect(server).await.unwrap();
    let mut stream = TlsConnector::from(config.config)
        .connect(config.authentication_name, tcp)
        .await
        .unwrap();
    let valid = query(41).into_wire().unwrap();
    let mut malformed = Vec::new();
    let mut duplicate = valid.clone();
    duplicate[11] = 2;
    duplicate.extend_from_slice(&valid[valid.len() - 11..]);
    malformed.push(duplicate);
    let mut nonroot = valid.clone();
    nonroot.splice(valid.len() - 11..valid.len() - 10, [1, b'x', 0]);
    malformed.push(nonroot);
    for count_offset in [7, 9] {
        let mut wrong_section = valid.clone();
        wrong_section[11] = 0;
        wrong_section[count_offset] = 1;
        malformed.push(wrong_section);
    }
    for options in [
        &[0, 12, 0, 0, 0, 12, 0, 0][..],    // Duplicate Padding.
        &[0, 15, 0, 1, 0, 0, 12, 0, 0][..], // Short EDE plus valid Padding.
    ] {
        let mut packet = valid[..valid.len() - 2].to_vec();
        packet.extend_from_slice(&(options.len() as u16).to_be_bytes());
        packet.extend_from_slice(options);
        malformed.push(packet);
    }
    for packet in malformed {
        write_frame(&mut stream, &packet).await.unwrap();
        let wire = time::timeout(Duration::from_secs(2), read_frame(&mut stream))
            .await
            .unwrap()
            .unwrap();
        let reply = Message::from_wire(&wire).unwrap();
        assert_eq!(reply.headers.rcode, dns::RCode::FormatError);
        assert_eq!(reply.headers.id, 41);
        assert_eq!(reply.questions.len(), 1);
        assert!(
            reply.questions[0]
                .qname
                .eq_dns(&query(41).questions[0].qname)
        );
        assert_eq!(reply.questions[0].qtype, QueryType::A);
        assert_eq!(reply.questions[0].qclass, QClassType::Class(ClassType::IN));
        assert!(reply.edns().unwrap().unwrap().padding().is_none());
    }
    write_frame(&mut stream, &query(42).into_wire().unwrap())
        .await
        .unwrap();
    let wire = time::timeout(Duration::from_secs(2), read_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::from_wire(&wire).unwrap().headers.rcode,
        dns::RCode::Ok
    );
    task.abort();
}

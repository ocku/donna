use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};

#[tokio::test]
async fn malformed_edns_returns_http200_with_formerr_without_padding() {
    let (server, task) = one_connection_server(|request: Message| async move {
        let valid_options = request
            .edns()
            .is_ok_and(|edns| edns.is_none_or(|edns| edns.validate_options().is_ok()));
        let mut edns = dns::Edns::default();
        edns.options.push(dns::EdnsOption::padding(16));
        Message {
            headers: Headers {
                qr: true,
                rcode: if valid_options {
                    dns::RCode::Ok
                } else {
                    dns::RCode::FormatError
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
    let transport = DohTransport::new(client_config(DohMethod::Post));
    let session = transport
        .connect(server, time::Instant::now() + Duration::from_secs(2))
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
    // A valid request after the malformed streams must succeed on this session.
    malformed.push(valid.clone());
    for method in [Method::GET, Method::POST] {
        for packet in &malformed {
            let get = method == Method::GET;
            let uri = if get {
                format!(
                    "https://localhost/dns-query?dns={}",
                    Base64UrlUnpadded::encode_string(packet)
                )
            } else {
                "https://localhost/dns-query".to_owned()
            };
            let request = Request::builder()
                .method(method.clone())
                .uri(uri)
                .header(header::CONTENT_TYPE, DOH_MEDIA_TYPE)
                .body(())
                .unwrap();
            let mut sender = session.as_ref().clone().ready().await.unwrap();
            let (response, mut body) = sender.send_request(request, get).unwrap();
            if !get {
                body.send_data(Bytes::copy_from_slice(packet), true)
                    .unwrap();
            }
            let response = time::timeout(Duration::from_secs(2), response)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let mut body = response.into_body();
            let mut wire = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                body.flow_control().release_capacity(chunk.len()).unwrap();
                wire.extend_from_slice(&chunk);
            }
            let reply = Message::from_wire(&wire).unwrap();
            assert_eq!(reply.headers.id, 41);
            assert_eq!(
                reply.headers.rcode,
                if packet == &valid {
                    dns::RCode::Ok
                } else {
                    dns::RCode::FormatError
                }
            );
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
    }
    task.abort();
}

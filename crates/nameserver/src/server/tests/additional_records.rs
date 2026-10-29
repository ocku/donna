use super::*;

#[tokio::test]
async fn srv_answers_include_target_address_records() {
    let server = NameServer::new();
    let service = name(&["_api", "_tcp", "example"]);
    let primary = name(&["primary", "other"]);
    let backup = name(&["backup", "other"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    service.clone(),
                    RecordType::SRV,
                    RData::SRV {
                        priority: 10,
                        weight: 5,
                        port: 443,
                        target: primary.clone(),
                    },
                ),
                record(
                    service.clone(),
                    RecordType::SRV,
                    RData::SRV {
                        priority: 20,
                        weight: 0,
                        port: 8443,
                        target: backup.clone(),
                    },
                ),
            ],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["other"]),
            ClassType::IN,
            300,
            vec![
                record(
                    primary.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 10)),
                ),
                record(
                    backup.clone(),
                    RecordType::AAAA,
                    RData::AAAA(Ipv6Addr::LOCALHOST),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: service,
            qtype: QueryType::SRV,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.answers.len(), 2);
    assert_eq!(response.additionals.len(), 2);
    assert!(response.additionals.iter().any(|record| {
        record.name.eq_dns(&primary) && record.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 10))
    }));
    assert!(response.additionals.iter().any(|record| {
        record.name.eq_dns(&backup) && record.rdata == RData::AAAA(Ipv6Addr::LOCALHOST)
    }));
}

#[tokio::test]
async fn additional_a_records_do_not_follow_cname_targets() {
    let server = NameServer::new();
    let relay = name(&["relay", "other"]);
    let mail = name(&["mail", "other"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["example"]),
                RecordType::MX,
                RData::MX {
                    preference: 10,
                    exchange: relay.clone(),
                },
            )],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["other"]),
            ClassType::IN,
            600,
            vec![
                record(relay, RecordType::CNAME, RData::CNAME(mail.clone())),
                record(mail, RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 25))),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::MX,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert_eq!(response.answers.len(), 1);
    assert!(response.additionals.is_empty());
}

#[tokio::test]
async fn ns_additional_records_do_not_follow_cname_targets() {
    let server = NameServer::new();
    let child = name(&["child", "example"]);
    let nameserver = name(&["ns", "other"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(child, RecordType::NS, RData::NS(nameserver.clone()))],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["other"]),
            ClassType::IN,
            600,
            vec![
                record(
                    nameserver,
                    RecordType::CNAME,
                    RData::CNAME(name(&["canonical", "other"])),
                ),
                record(
                    name(&["canonical", "other"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "child", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert_eq!(response.authorities.len(), 1);
    assert!(response.additionals.is_empty());
}

#[tokio::test]
async fn referral_prefers_authoritative_data_from_another_hosted_zone_over_glue() {
    let server = NameServer::new();
    let child = name(&["child", "example"]);
    let deep = name(&["deep", "child", "example"]);
    let nameserver = name(&["ns", "deep", "child", "example"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record_with_ttl(
                    child.clone(),
                    RecordType::NS,
                    90,
                    RData::NS(nameserver.clone()),
                ),
                record_with_ttl(
                    nameserver.clone(),
                    RecordType::A,
                    110,
                    RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                ),
            ],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            deep,
            ClassType::IN,
            600,
            vec![record_with_ttl(
                nameserver.clone(),
                RecordType::A,
                700,
                RData::A(Ipv4Addr::new(192, 0, 2, 99)),
            )],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "child", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(!response.headers.aa);
    assert!(matches!(
        response.authorities.as_slice(),
        [ResourceRecord {
            name: owner,
            ttl: 90,
            rdata: RData::NS(target),
            ..
        }] if owner.eq_dns(&child) && target.eq_dns(&nameserver)
    ));
    assert!(matches!(
        response.additionals.as_slice(),
        [ResourceRecord {
            name: owner,
            ttl: 700,
            rdata: RData::A(address),
            ..
        }] if owner.eq_dns(&nameserver) && *address == Ipv4Addr::new(192, 0, 2, 99)
    ));
}

#[tokio::test]
async fn referral_does_not_use_glue_after_an_authoritative_name_error() {
    let server = NameServer::new();
    let child = name(&["child", "example"]);
    let deep = name(&["deep", "child", "example"]);
    let nameserver = name(&["ns", "deep", "child", "example"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(child.clone(), RecordType::NS, RData::NS(nameserver.clone())),
                record(
                    nameserver,
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                ),
            ],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(deep, ClassType::IN, 600, Vec::new()))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "child", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(!response.headers.aa);
    assert_eq!(response.authorities.len(), 1);
    assert!(response.additionals.is_empty());
}

#[tokio::test]
async fn referral_falls_back_to_in_bailiwick_glue() {
    let server = NameServer::new();
    let child = name(&["child", "example"]);
    let nameserver = name(&["ns", "child", "example"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record_with_ttl(
                    child.clone(),
                    RecordType::NS,
                    90,
                    RData::NS(nameserver.clone()),
                ),
                record_with_ttl(
                    nameserver.clone(),
                    RecordType::A,
                    110,
                    RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "child", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert!(matches!(
        response.additionals.as_slice(),
        [ResourceRecord {
            name: owner,
            ttl: 110,
            rdata: RData::A(address),
            ..
        }] if owner.eq_dns(&nameserver) && *address == Ipv4Addr::new(192, 0, 2, 53)
    ));
}

#[tokio::test]
async fn any_class_uses_each_class_nearest_hosted_zone() {
    let server = NameServer::new();
    let qname = name(&["www", "child", "example"]);
    server
        .install(make_zone(
            name(&["child", "example"]),
            ClassType::IN,
            300,
            vec![class_record_with_ttl(
                qname.clone(),
                RecordType::TXT,
                ClassType::IN,
                130,
                RData::TXT(vec![b"in-child".to_vec()]),
            )],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::CH,
            400,
            vec![class_record_with_ttl(
                qname.clone(),
                RecordType::TXT,
                ClassType::CH,
                140,
                RData::TXT(vec![b"ch-parent".to_vec()]),
            )],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname,
            qtype: QueryType::TXT,
            qclass: QClassType::ANY,
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(!response.headers.aa);
    assert_eq!(response.answers.len(), 2);
    assert!(response.answers.iter().any(|record| {
        record.class == ClassType::IN
            && record.ttl == 130
            && record.rdata == RData::TXT(vec![b"in-child".to_vec()])
    }));
    assert!(response.answers.iter().any(|record| {
        record.class == ClassType::CH
            && record.ttl == 140
            && record.rdata == RData::TXT(vec![b"ch-parent".to_vec()])
    }));
}

#[tokio::test]
async fn cname_to_an_unserved_target_is_an_authoritative_answer() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .headers(Headers::default())
        .questions([Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;
    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::CNAME(_),
            ..
        }]
    ));
}

#[tokio::test]
async fn responses_echo_the_question_and_copy_id_rd_and_opcode() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .headers(Headers {
            id: 7,
            rd: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["WwW", "ExAmPlE"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query.clone()).await;

    assert_eq!(response.headers.id, 7);
    assert!(response.headers.qr);
    assert!(response.headers.rd);
    assert!(!response.headers.ra);
    assert_eq!(response.headers.opcode, query.headers.opcode);
    assert_eq!(response.questions.len(), 1);
    assert_eq!(response.questions[0].qname, query.questions[0].qname);
    assert_eq!(response.questions[0].qtype, query.questions[0].qtype);
    assert_eq!(response.questions[0].qclass, query.questions[0].qclass);
    assert!(matches!(response.answers.as_slice(), [ResourceRecord {
            name: owner,
            rdata: RData::A(_),
            ..
        }] if owner.eq_dns(&name(&["www", "example"]))));
}

#[tokio::test]
async fn out_of_zone_names_are_refused_without_authority() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["other"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(!response.headers.aa);
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
}

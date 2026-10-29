use super::*;

#[tokio::test]
async fn axfr_packs_multiple_records_into_messages_within_the_tcp_limit() {
    let server = axfr_server();
    let records = (0..3)
        .map(|index| {
            record(
                name(&[&format!("opaque-{index}"), "example"]),
                RecordType::Unknown(65_000),
                RData::Unknown(vec![index as u8; 40_000]),
            )
        })
        .collect();
    server
        .install(make_zone(name(&["example"]), ClassType::IN, 300, records))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let responses = server.handle_transfer(axfr_peer(), query).await;

    assert!(responses.len() > 1);
    assert_eq!(responses[0].questions.len(), 1);
    assert!(
        responses
            .iter()
            .skip(1)
            .all(|response| response.questions.is_empty())
    );
    assert!(responses.iter().all(|response| {
        !response.answers.is_empty() && response.into_wire().unwrap().len() <= usize::from(u16::MAX)
    }));
    assert!(responses.iter().any(|response| response.answers.len() > 1));
    assert_eq!(
        responses
            .iter()
            .flat_map(|response| &response.answers)
            .count(),
        6
    );
    assert_eq!(responses.first().unwrap().answers[0].rtype, RecordType::SOA);
    assert_eq!(
        responses.last().unwrap().answers.last().unwrap().rtype,
        RecordType::SOA
    );
}

#[tokio::test]
async fn axfr_stream_production_waits_for_bounded_channel_capacity_and_cancels() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountingRecords {
        records: std::vec::IntoIter<ResourceRecord>,
        advanced: Arc<AtomicUsize>,
    }

    impl Iterator for CountingRecords {
        type Item = ResourceRecord;

        fn next(&mut self) -> Option<Self::Item> {
            let record = self.records.next()?;
            self.advanced.fetch_add(1, Ordering::SeqCst);
            Some(record)
        }
    }

    let zone = make_zone(
        name(&["example"]),
        ClassType::IN,
        300,
        (0..4)
            .map(|index| {
                record(
                    name(&[&format!("opaque-{index}"), "example"]),
                    RecordType::Unknown(65_000),
                    RData::Unknown(vec![index as u8; 40_000]),
                )
            })
            .collect(),
    );
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let advanced = Arc::new(AtomicUsize::new(0));
    let records = CountingRecords {
        records: zone.transfer_records().into_iter(),
        advanced: Arc::clone(&advanced),
    };
    let (responses, mut receiver) = mpsc::channel(1);
    let producer =
        tokio::spawn(async move { stream_axfr_responses(&query, records, responses, None).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while receiver.len() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let stalled_at = advanced.load(Ordering::SeqCst);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(receiver.len(), 1);
    assert_eq!(advanced.load(Ordering::SeqCst), stalled_at);
    assert!(!producer.is_finished());

    let _ = receiver.recv().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while receiver.len() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(advanced.load(Ordering::SeqCst) > stalled_at);

    drop(receiver);
    assert!(!producer.await.unwrap());
}

#[tokio::test]
async fn axfr_qclass_any_is_a_format_error() {
    let server = axfr_server();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::ANY,
        }])
        .build()
        .unwrap();

    let responses = server.handle_transfer(axfr_peer(), query).await;

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].headers.rcode, RCode::FormatError);
    assert_eq!(responses[0].questions.len(), 1);
    assert!(responses[0].answers.is_empty());
}

#[tokio::test]
async fn authorized_axfr_for_a_non_authoritative_name_or_class_returns_notauth() {
    let server = axfr_server();
    server.install(test_zone()).await.unwrap();

    for (qname, qclass) in [
        (name(&["www", "example"]), QClassType::Class(ClassType::IN)),
        (name(&["other"]), QClassType::Class(ClassType::IN)),
        (name(&["example"]), QClassType::Class(ClassType::CH)),
    ] {
        let query = Message::builder()
            .questions([Question {
                qname,
                qtype: QueryType::AXFR,
                qclass,
            }])
            .build()
            .unwrap();

        let responses = server.handle_transfer(axfr_peer(), query).await;
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].headers.rcode, RCode::NotAuthoritative);
        assert_eq!(responses[0].questions.len(), 1);
        assert!(responses[0].answers.is_empty());
        let packet = responses[0].into_wire().unwrap();
        assert_eq!(
            Message::from_wire(&packet).unwrap().headers.rcode,
            RCode::NotAuthoritative
        );
    }
}

#[tokio::test]
async fn any_class_does_not_emit_non_authoritative_name_error() {
    let server = NameServer::new();
    server
        .install(test_zone_for_class(ClassType::IN, None))
        .await
        .unwrap();
    server
        .install(test_zone_for_class(ClassType::CH, None))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["missing", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::ANY,
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(!response.headers.aa);
    assert!(response.answers.is_empty());
    assert_eq!(
        response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::SOA)
            .count(),
        2
    );
}

#[tokio::test]
async fn any_class_does_not_return_a_negative_from_only_one_class() {
    for in_record in [
        None,
        Some((
            RecordType::MX,
            RData::MX {
                preference: 10,
                exchange: DomainName::root(),
            },
        )),
    ] {
        let server = NameServer::new();
        server
            .install(test_zone_for_class(ClassType::IN, in_record))
            .await
            .unwrap();
        server
            .install(test_zone_for_class(
                ClassType::CH,
                Some((RecordType::TXT, RData::TXT(vec![b"ch".to_vec()]))),
            ))
            .await
            .unwrap();
        let query = Message::builder()
            .questions([Question {
                qname: name(&["www", "example"]),
                qtype: QueryType::TXT,
                qclass: QClassType::ANY,
            }])
            .build()
            .unwrap();

        let response = server.handle(query).await;
        assert_eq!(response.headers.rcode, RCode::Ok);
        assert!(!response.headers.aa);
        assert!(response.authorities.is_empty());
        assert!(matches!(
            response.answers.as_slice(),
            [ResourceRecord {
                class: ClassType::CH,
                rdata: RData::TXT(strings),
                ..
            }] if strings == &vec![b"ch".to_vec()]
        ));
    }
}

#[tokio::test]
async fn any_class_propagates_a_server_failure_from_one_class() {
    // A per-class result that is neither NOERROR nor NXDOMAIN must surface as
    // the aggregate RCODE instead of being masked by another class's data.
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    name(&["www", "example"]),
                    RecordType::CNAME,
                    RData::CNAME(name(&["loop", "example"])),
                ),
                record(
                    name(&["loop", "example"]),
                    RecordType::CNAME,
                    RData::CNAME(name(&["www", "example"])),
                ),
            ],
        ))
        .await
        .unwrap();
    server
        .install(test_zone_for_class(
            ClassType::CH,
            Some((RecordType::TXT, RData::TXT(vec![b"ch".to_vec()]))),
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::TXT,
            qclass: QClassType::ANY,
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::ServerFailure);
    assert!(!response.headers.aa);
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert!(response.additionals.is_empty());
}

#[tokio::test]
async fn qtype_cname_returns_the_alias_without_following_it() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::CNAME,
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
            rdata: RData::CNAME(target),
            ..
        }] if target.eq_dns(&name(&["target", "other"]))
    ));
}

#[tokio::test]
async fn qtype_any_at_a_cname_owner_returns_only_the_cname() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::ANY,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert_eq!(response.answers.len(), 1);
    assert!(matches!(
        response.answers[0],
        ResourceRecord {
            rdata: RData::CNAME(_),
            ..
        }
    ));
}

#[tokio::test]
async fn exact_owner_data_takes_precedence_over_wildcards() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    name(&["*", "example"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 99)),
                ),
                record(
                    name(&["www", "example"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::A(address),
            ..
        }] if *address == Ipv4Addr::new(192, 0, 2, 1)
    ));
}

#[tokio::test]
async fn wildcards_match_names_several_labels_below_the_encloser() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["*", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 99)),
            )],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["a", "b", "example"]),
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
            name: owner,
            rdata: RData::A(address),
            ..
        }] if owner.eq_dns(&name(&["a", "b", "example"]))
            && *address == Ipv4Addr::new(192, 0, 2, 99)
    ));
}

use super::*;

#[tokio::test]
async fn dname_redirects_descendants_but_not_its_owner() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    name(&["old", "example"]),
                    RecordType::DNAME,
                    RData::DNAME(name(&["new", "example"])),
                ),
                record(
                    name(&["old", "example"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ),
                record(
                    name(&["a", "new", "example"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 2)),
                ),
            ],
        ))
        .await
        .unwrap();
    let ask = |labels: &[&str], qtype| {
        Message::builder()
            .questions([Question {
                qname: name(labels),
                qtype,
                qclass: QClassType::Class(ClassType::IN),
            }])
            .build()
            .unwrap()
    };
    let owner = server.handle(ask(&["old", "example"], QueryType::A)).await;
    assert_eq!(owner.headers.rcode, RCode::Ok);
    assert_eq!(owner.answers.len(), 1);
    assert_eq!(owner.answers[0].rtype, RecordType::A);
    let redirected = server
        .handle(ask(&["a", "old", "example"], QueryType::A))
        .await;
    assert_eq!(redirected.headers.rcode, RCode::Ok);
    assert!(redirected.headers.aa);
    assert_eq!(
        redirected
            .answers
            .iter()
            .map(|r| r.rtype)
            .collect::<Vec<_>>(),
        vec![RecordType::DNAME, RecordType::CNAME, RecordType::A]
    );
    assert!(
        matches!(&redirected.answers[1].rdata, RData::CNAME(target) if target.eq_dns(&name(&["a", "new", "example"])))
    );
    assert_eq!(redirected.answers[0].ttl, redirected.answers[1].ttl);
    let cname = server
        .handle(ask(&["a", "old", "example"], QueryType::CNAME))
        .await;
    assert_eq!(
        cname.answers.iter().map(|r| r.rtype).collect::<Vec<_>>(),
        vec![RecordType::DNAME, RecordType::CNAME]
    );
}

#[tokio::test]
async fn dname_overflow_returns_yxdomain_with_the_dname() {
    let server = NameServer::new();
    let destination = DomainName::from_labels(vec![
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 60],
    ])
    .unwrap();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["old", "example"]),
                RecordType::DNAME,
                RData::DNAME(destination),
            )],
        ))
        .await
        .unwrap();
    let response = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: name(&["prefix", "old", "example"]),
                    qtype: QueryType::A,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap(),
        )
        .await;
    assert_eq!(response.headers.rcode, RCode::YXDomain);
    assert!(response.headers.aa);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].rtype, RecordType::DNAME);
    use dns::{FromWire, IntoWire};
    let wire = response.into_wire().unwrap();
    assert_eq!(
        Message::from_wire(&wire).unwrap().headers.rcode,
        RCode::YXDomain
    );
    let any_class = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: name(&["prefix", "old", "example"]),
                    qtype: QueryType::A,
                    qclass: QClassType::ANY,
                }])
                .build()
                .unwrap(),
        )
        .await;
    assert_eq!(any_class.headers.rcode, RCode::YXDomain);
    assert_eq!(any_class.answers.len(), 1);
    assert_eq!(any_class.answers[0].rtype, RecordType::DNAME);
    assert!(any_class.into_wire().is_ok());
}

#[tokio::test]
async fn dname_occludes_descendant_data_and_delegations() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    name(&["old", "example"]),
                    RecordType::DNAME,
                    RData::DNAME(name(&["elsewhere", "other"])),
                ),
                record(
                    name(&["cut", "old", "example"]),
                    RecordType::NS,
                    RData::NS(name(&["ns", "other"])),
                ),
                record(
                    name(&["data", "old", "example"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 4)),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["cut", "old", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let reply = server.handle(query).await;
    assert!(reply.headers.aa);
    assert_eq!(
        reply.answers.iter().map(|r| r.rtype).collect::<Vec<_>>(),
        vec![RecordType::DNAME, RecordType::CNAME]
    );
    assert!(reply.authorities.is_empty());
}

#[tokio::test]
async fn dname_negative_response_is_encodable_and_signature_covers_only_the_dname() {
    let server = NameServer::new();
    let owner = name(&["old", "example"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    owner.clone(),
                    RecordType::DNAME,
                    RData::DNAME(name(&["missing", "example"])),
                ),
                rrsig(owner, RecordType::DNAME, 2),
            ],
        ))
        .await
        .unwrap();
    let response = server
        .handle(query_with_do(
            name(&["a", "old", "example"]),
            QueryType::A,
            true,
        ))
        .await;
    assert_eq!(response.headers.rcode, RCode::NameError);
    assert_eq!(
        response.answers.iter().map(|r| r.rtype).collect::<Vec<_>>(),
        vec![RecordType::DNAME, RecordType::RRSIG, RecordType::CNAME]
    );
    assert!(
        response
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::SOA)
    );
    use dns::{FromWire, IntoWire};
    let parsed = Message::from_wire(&response.into_wire().unwrap()).unwrap();
    assert_eq!(parsed.headers.rcode, RCode::NameError);
}

#[tokio::test]
async fn dynamic_update_replaces_dname_and_ignores_conflicting_cname() {
    let persistence = Arc::new(MemoryUpdatePersistence::default());
    let server = update_server(Arc::clone(&persistence));
    server.install(test_zone()).await.unwrap();
    let owner = name(&["redirect", "example"]);
    for destination in [name(&["first", "other"]), name(&["second", "other"])] {
        let request = update_request(
            [],
            [record(
                owner.clone(),
                RecordType::DNAME,
                RData::DNAME(destination),
            )],
        );
        assert_eq!(server.handle(request).await.headers.rcode, RCode::Ok);
    }
    let request = update_request(
        [],
        [record(
            owner.clone(),
            RecordType::CNAME,
            RData::CNAME(name(&["wrong", "other"])),
        )],
    );
    assert_eq!(server.handle(request).await.headers.rcode, RCode::Ok);
    let response = server
        .handle(query_with_do(owner, QueryType::DNAME, false))
        .await;
    assert_eq!(response.answers.len(), 1);
    assert!(
        matches!(&response.answers[0].rdata, RData::DNAME(target) if target.eq_dns(&name(&["second", "other"]))),
        "{:?}",
        response.answers
    );
}

#[tokio::test]
async fn hosted_child_under_dname_cannot_bypass_ancestor_redirection() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["old", "example"]),
                RecordType::DNAME,
                RData::DNAME(name(&["new", "other"])),
            )],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["child", "old", "example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["www", "child", "old", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 9)),
            )],
        ))
        .await
        .unwrap();
    for qclass in [QClassType::Class(ClassType::IN), QClassType::ANY] {
        for qtype in [QueryType::A, QueryType::DS] {
            let response = server
                .handle(
                    Message::builder()
                        .questions([Question {
                            qname: name(&["www", "child", "old", "example"]),
                            qtype,
                            qclass,
                        }])
                        .build()
                        .unwrap(),
                )
                .await;
            assert_eq!(response.headers.rcode, RCode::Ok);
            assert_eq!(
                response.answers.iter().map(|r| r.rtype).collect::<Vec<_>>(),
                vec![RecordType::DNAME, RecordType::CNAME]
            );
            assert!(
                matches!(&response.answers[1].rdata, RData::CNAME(target) if target.eq_dns(&name(&["www", "child", "new", "other"])))
            );
        }
    }
}

#[tokio::test]
async fn delegated_ancestor_hides_parent_dname_from_hosted_child() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    name(&["child", "example"]),
                    RecordType::NS,
                    RData::NS(name(&["ns", "other"])),
                ),
                record(
                    name(&["old", "child", "example"]),
                    RecordType::DNAME,
                    RData::DNAME(name(&["new", "other"])),
                ),
            ],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["child", "example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["www", "old", "child", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 9)),
            )],
        ))
        .await
        .unwrap();
    for qclass in [QClassType::Class(ClassType::IN), QClassType::ANY] {
        let response = server
            .handle(
                Message::builder()
                    .questions([Question {
                        qname: name(&["www", "old", "child", "example"]),
                        qtype: QueryType::A,
                        qclass,
                    }])
                    .build()
                    .unwrap(),
            )
            .await;
        assert_eq!(response.headers.rcode, RCode::Ok);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rtype, RecordType::A);
    }
}

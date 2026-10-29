use super::*;

#[tokio::test]
async fn incomplete_external_and_delegated_cname_answers_are_encodable() {
    let child = name(&["child", "example"]);
    for target in [
        name(&["www", "outside"]),
        name(&["www", "child", "example"]),
    ] {
        let server = NameServer::new();
        let alias = name(&["alias", "example"]);
        server
            .install(make_zone(
                name(&["example"]),
                ClassType::IN,
                30,
                vec![
                    record(
                        alias.clone(),
                        RecordType::CNAME,
                        RData::CNAME(target.clone()),
                    ),
                    record(child.clone(), RecordType::NS, RData::NS(DomainName::root())),
                ],
            ))
            .await
            .unwrap();
        for kind in [
            QueryType::A,
            QueryType::AAAA,
            QueryType::NS,
            QueryType::SOA,
            QueryType::DS,
            QueryType::TXT,
        ] {
            let response = server
                .handle(query_with_do(alias.clone(), kind, false))
                .await;
            assert!(response.headers.aa);
            assert_eq!(response.headers.rcode, RCode::Ok);
            assert_eq!(response.answers.len(), 1);
            assert!(
                matches!(&response.answers[0].rdata, RData::CNAME(name) if name.eq_dns(&target))
            );
            assert!(response.into_wire().is_ok());
        }
    }
}

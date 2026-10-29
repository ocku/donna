use super::*;

#[tokio::test]
async fn wildcard_cname_retains_proofs_across_terminal_lookup_kinds() {
    for terminal in ["nxdomain", "nodata", "referral", "answer"] {
        let server = NameServer::new();
        let expanded = name(&["expanded", "example"]);
        let target = name(&["target", "other"]);
        let wildcard = name(&["*", "example"]);
        server
            .install(add_nsec3_chain(
                make_zone(
                    name(&["example"]),
                    ClassType::IN,
                    300,
                    vec![
                        record(
                            wildcard.clone(),
                            RecordType::CNAME,
                            RData::CNAME(target.clone()),
                        ),
                        rrsig(wildcard, RecordType::CNAME, 1),
                    ],
                ),
                false,
            ))
            .await
            .unwrap();
        let records = match terminal {
            "nxdomain" => vec![],
            "nodata" => vec![record(
                target.clone(),
                RecordType::AAAA,
                RData::AAAA(Ipv6Addr::LOCALHOST),
            )],
            "referral" => vec![record(
                target.clone(),
                RecordType::NS,
                RData::NS(DomainName::root()),
            )],
            "answer" => vec![
                record(target.clone(), RecordType::A, RData::A(Ipv4Addr::LOCALHOST)),
                rrsig(target.clone(), RecordType::A, 2),
            ],
            _ => unreachable!(),
        };
        server
            .install(add_nsec3_chain(
                make_zone(name(&["other"]), ClassType::IN, 300, records),
                false,
            ))
            .await
            .unwrap();

        // The direct wildcard CNAME answer supplies the complete expansion
        // proof; the direct target query supplies the terminal proof set.
        let wildcard_response = server
            .handle(query_with_do(expanded.clone(), QueryType::CNAME, true))
            .await;
        let terminal_response = server
            .handle(query_with_do(target, QueryType::A, true))
            .await;
        let response = server
            .handle(query_with_do(expanded.clone(), QueryType::A, true))
            .await;
        assert_eq!(response.headers.rcode, terminal_response.headers.rcode);
        assert!(
            response.answers.iter().any(|record| {
                record.name.eq_dns(&expanded) && record.rtype == RecordType::CNAME
            })
        );
        assert!(
            wildcard_response
                .authorities
                .iter()
                .any(|record| { record.rtype == RecordType::NSEC3 })
        );
        assert!(wildcard_response.authorities.iter().any(|record| {
            matches!(&record.rdata, RData::RRSIG(signature)
                if signature.type_covered == u16::from(RecordType::NSEC3))
        }));
        let mut expected = wildcard_response.authorities;
        for record in terminal_response.authorities {
            if !crate::zone::response::contains_record(&expected, &record) {
                expected.push(record);
            }
        }
        assert_eq!(
            response.authorities.len(),
            expected.len(),
            "terminal {terminal}"
        );
        for record in expected {
            assert!(
                crate::zone::response::contains_record(&response.authorities, &record),
                "missing {record:?} for terminal {terminal}"
            );
        }
    }
}

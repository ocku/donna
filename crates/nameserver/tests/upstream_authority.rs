//! Public-API regression corpus independently derived from BIND's auth tests.
//! Provenance and policy boundaries: tests/behaviour/README.md.
use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord, master::MasterFile,
};
use nameserver::{NameServer, Zone};

fn records(text: &str) -> Vec<ResourceRecord> {
    MasterFile::parse(&text.replace("; ", "\n"), None)
        .unwrap()
        .records
}

fn same_records(actual: &[ResourceRecord], expected: &[ResourceRecord]) -> bool {
    let mut remaining: Vec<_> = actual.iter().collect();
    for record in expected {
        let Some(index) = remaining
            .iter()
            .position(|candidate| candidate.eq_dns(record) && candidate.ttl == record.ttl)
        else {
            return false;
        };
        remaining.swap_remove(index);
    }
    remaining.is_empty()
}

#[tokio::test]
async fn bind_authority_alias_corpus() {
    let apex = DomainName::from_dotted("example.test.").unwrap();
    let master = MasterFile::parse(
        include_str!("../../../tests/behaviour/authority.zone"),
        Some(apex.clone()),
    )
    .unwrap();
    let server = NameServer::new();
    server
        .install(Zone::from_master(apex.clone(), master).unwrap())
        .await
        .unwrap();
    for row in include_str!("../../../tests/behaviour/authority.tsv").lines() {
        if row.starts_with('#') || row.is_empty() {
            continue;
        }
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 6, "{row}");
        let [id, qname, qtype, rcode, kind, expected] = fields.as_slice() else {
            unreachable!()
        };
        let qtype = match *qtype {
            "A" => QueryType::A,
            "AAAA" => QueryType::AAAA,
            "CNAME" => QueryType::CNAME,
            "DNAME" => QueryType::DNAME,
            "ANY" => QueryType::ANY,
            other => panic!("unknown query type: {other}"),
        };
        let rcode = match *rcode {
            "NOERROR" => RCode::Ok,
            "NXDOMAIN" => RCode::NameError,
            other => panic!("unknown RCODE: {other}"),
        };
        let expected = records(expected);
        for rd in [false, true] {
            let query = Message::builder()
                .headers(Headers {
                    id: 42,
                    rd,
                    ..Headers::default()
                })
                .questions([Question {
                    qname: DomainName::from_dotted(qname).unwrap(),
                    qtype,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap();
            // Check repeated public-API responses; the network probe also exercises listeners.
            for repeat in 0..40 {
                let reply = server.handle(query.clone()).await;
                let label = format!("{id}, RD={rd}, repeat={repeat}");
                assert_eq!(reply.headers.rcode, rcode, "{label}");
                assert!(
                    reply.headers.qr && !reply.headers.tc && !reply.headers.ra,
                    "{label}"
                );
                assert_eq!(reply.headers.rd, rd, "{label}");
                assert_eq!(reply.headers.aa, *kind != "referral", "{label}");
                assert_eq!(reply.headers.id, query.headers.id, "{label}");
                assert_eq!(reply.questions.len(), 1, "{label}");
                assert!(
                    reply.questions[0].qname.eq_dns(&query.questions[0].qname),
                    "{label}"
                );
                assert_eq!(reply.questions[0].qtype, qtype, "{label}");
                assert_eq!(
                    reply.questions[0].qclass, query.questions[0].qclass,
                    "{label}"
                );
                assert!(
                    same_records(&reply.answers, &expected),
                    "{label}: expected {expected:?}, got {:?}",
                    reply.answers
                );
                let soas: Vec<_> = reply
                    .authorities
                    .iter()
                    .filter(|r| r.rtype == RecordType::SOA)
                    .collect();
                if *kind == "negative" {
                    assert_eq!(soas.len(), 1, "{label}");
                    assert!(soas[0].name.eq_dns(&apex), "{label}");
                    assert_eq!(soas[0].class, ClassType::IN, "{label}");
                    assert_eq!(soas[0].ttl, 30, "{label}");
                    assert!(
                        matches!(&soas[0].rdata, RData::SOA { minimum: 30, .. }),
                        "{label}"
                    );
                } else {
                    assert!(soas.is_empty(), "{label}");
                }
                if *kind == "referral" {
                    assert!(
                        same_records(
                            &reply.authorities,
                            &records("cut.example.test. 300 IN NS ns.cut.example.test.")
                        ),
                        "{label}"
                    );
                    let glue = records("ns.cut.example.test. 300 IN A 192.0.2.54");
                    assert!(
                        reply
                            .additionals
                            .iter()
                            .any(|r| r.eq_dns(&glue[0]) && r.ttl == glue[0].ttl),
                        "{label}"
                    );
                }
            }
        }
    }
}

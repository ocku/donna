use super::*;
use crate::{
    name::{dns_name_key_into, suffixes},
    server::zone_index::{ZoneIndex, authoritative_zone_key},
};

// Original multi-pass selector retained as an oracle for routing changes.
fn original<'a>(zones: &'a ZoneIndex, question: &Question, key: &[u8]) -> Option<&'a Zone> {
    let matches = |zone: &&Arc<Zone>| match question.qclass {
        QClassType::Class(class) => zone.class == class,
        QClassType::ANY => true,
        QClassType::Unknown(code) => zone.class.value() == code,
    };
    if let Some(zone) = suffixes(key)
        .filter_map(|suffix| zones.by_apex.get(suffix))
        .flat_map(|at_apex| at_apex.iter())
        .filter(matches)
        .filter(|zone| zone.redirects_by_dname_key(key))
        .last()
    {
        return Some(zone.as_ref());
    }
    if question.qtype == QueryType::DS
        && let Some(parent) = suffixes(key).skip(1).find_map(|suffix| {
            zones
                .by_apex
                .get(suffix)?
                .iter()
                .filter(matches)
                .find(|zone| zone.is_authoritative_owner(&question.qname))
                .map(Arc::as_ref)
        })
    {
        return Some(parent);
    }
    suffixes(key).find_map(|suffix| {
        zones
            .by_apex
            .get(suffix)?
            .iter()
            .find(matches)
            .map(Arc::as_ref)
    })
}

#[tokio::test]
async fn multi_zone_single_pass_matches_original_with_dname() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            30,
            vec![record(
                name(&["old", "example"]),
                RecordType::DNAME,
                RData::DNAME(name(&["new", "other"])),
            )],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(name(&["example"]), ClassType::CH, 30, vec![]))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["child", "old", "example"]),
            ClassType::IN,
            30,
            vec![],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(name(&["other"]), ClassType::IN, 30, vec![]))
        .await
        .unwrap();
    let zones = server.zones.read().await.unwrap();
    for qname in [
        name(&["example"]),
        name(&["old", "example"]),
        name(&["child", "old", "example"]),
        name(&["www", "child", "old", "example"]),
        name(&["www", "example"]),
        name(&["www", "other"]),
        name(&["unknown"]),
    ] {
        for qtype in [QueryType::A, QueryType::DS, QueryType::DNAME] {
            for qclass in [
                QClassType::Class(ClassType::IN),
                QClassType::Class(ClassType::CH),
                QClassType::ANY,
                QClassType::Unknown(1),
                QClassType::Unknown(65000),
            ] {
                let question = Question {
                    qname: qname.clone(),
                    qtype,
                    qclass,
                };
                let mut storage = [0; 255];
                let key = dns_name_key_into(&qname, &mut storage);
                let expected = original(&zones, &question, key);
                let actual = authoritative_zone_key(&zones, &question, key);
                assert!(
                    match (expected, actual) {
                        (Some(a), Some(b)) => std::ptr::eq(a, b),
                        (None, None) => true,
                        _ => false,
                    },
                    "catalog mismatch for {question:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn catalog_shortcut_matches_original_zone_selection() {
    let catalogs = [
        vec![],
        vec![(DomainName::root(), ClassType::IN)],
        vec![(name(&["example"]), ClassType::IN)],
        vec![(name(&["example"]), ClassType::CH)],
        vec![
            (name(&["example"]), ClassType::IN),
            (name(&["example"]), ClassType::CH),
        ],
        vec![
            (name(&["example"]), ClassType::IN),
            (name(&["child", "example"]), ClassType::IN),
        ],
    ];
    let names = [
        DomainName::root(),
        name(&["EXAMPLE"]),
        name(&["child", "example"]),
        name(&["notexample"]),
        name(&["child", "other"]),
        DomainName::from_labels(vec![vec![0, 255, b'A'], b"EXAMPLE".to_vec()]).unwrap(),
        DomainName::from_labels(vec![
            vec![b'X'; 63],
            vec![b'X'; 63],
            vec![b'X'; 63],
            vec![b'X'; 61],
        ])
        .unwrap(),
    ];
    for catalog in catalogs {
        let server = NameServer::new();
        for (apex, class) in catalog {
            let records = if apex == DomainName::root() {
                vec![class_record(
                    DomainName::root(),
                    RecordType::A,
                    class,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                )]
            } else {
                vec![]
            };
            server
                .install(make_zone(apex, class, 30, records))
                .await
                .unwrap();
        }
        let zones = server.zones.read().await.unwrap();
        for qname in &names {
            for qtype in [QueryType::A, QueryType::DS, QueryType::SOA] {
                for qclass in [
                    QClassType::Class(ClassType::IN),
                    QClassType::Class(ClassType::CH),
                    QClassType::ANY,
                    QClassType::Unknown(1),
                    QClassType::Unknown(65000),
                ] {
                    let question = Question {
                        qname: qname.clone(),
                        qtype,
                        qclass,
                    };
                    let mut storage = [0; 255];
                    let key = dns_name_key_into(qname, &mut storage);
                    let expected = original(&zones, &question, key);
                    let actual = authoritative_zone_key(&zones, &question, key);
                    assert!(
                        match (expected, actual) {
                            (Some(a), Some(b)) => std::ptr::eq(a, b),
                            (None, None) => true,
                            _ => false,
                        },
                        "catalog mismatch for {question:?}"
                    );
                }
            }
        }
    }
}

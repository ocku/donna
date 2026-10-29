use super::*;
use dns::{ClassType, DomainName, QueryType, RecordType};

fn question(index: usize) -> Question {
    Question {
        qname: DomainName::from_dotted(&format!("missing-{index}.example.")).unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn negative() -> Message {
    Message {
        headers: Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        questions: vec![],
        answers: vec![],
        additionals: vec![],
        authorities: vec![ResourceRecord {
            name: DomainName::from_dotted("example.").unwrap(),
            rtype: RecordType::SOA,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::SOA {
                mname: DomainName::from_dotted("ns.example.").unwrap(),
                rname: DomainName::from_dotted("hostmaster.example.").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 900,
                expire: 86400,
                minimum: 60,
            },
        }],
    }
}

#[test]
fn owner_lookup_keeps_type_class_and_expiry_across_the_scan_boundary() {
    let cache = NegativeCache::new(32);
    let mut reply = negative();
    reply.headers.rcode = RCode::Ok;
    let mut queries = Vec::new();
    for code in 65000..65020 {
        let query = Question {
            qtype: QueryType::Unknown(code),
            ..question(0)
        };
        assert!(cache.insert(&query, &reply, true, Duration::from_secs(60)));
        queries.push(query);
        for query in &queries {
            assert!(cache.get(query).is_some());
            let mut other_class = query.clone();
            other_class.qclass = QClassType::Class(ClassType::CH);
            assert!(cache.get(&other_class).is_none());
        }
        assert!(cache.get(&question(0)).is_none());
    }
    {
        let mut entries = cache.entries.lock().unwrap();
        let now = Instant::now();
        for index in 0..entries.len() - 1 {
            entries.modify(index, |entry| {
                entry.expires_at = now - Duration::from_secs(1)
            });
        }
    }
    for query in &queries[..queries.len() - 1] {
        assert!(cache.get(query).is_none());
    }
    assert!(cache.get(queries.last().unwrap()).is_some());
}

#[test]
fn expired_exact_negative_key_is_replaced_even_during_incremental_cleanup() {
    let cache = NegativeCache::new(128);
    let reply = negative();
    for index in 0..100 {
        assert!(cache.insert(&question(index), &reply, true, Duration::from_secs(60)));
    }
    {
        let mut entries = cache.entries.lock().unwrap();
        let now = Instant::now();
        for index in 0..100 {
            entries.modify(index, |entry| {
                entry.expires_at = now - Duration::from_secs(if index == 99 { 1 } else { 10 })
            });
        }
    }
    assert!(cache.insert(&question(99), &reply, true, Duration::from_secs(60)));
    assert!(cache.get(&question(99)).is_some());
    let entries = cache.entries.lock().unwrap();
    let key = NegativeKey::name(&question(99).qname, ClassType::IN);
    assert_eq!(
        entries
            .values
            .iter()
            .filter(|entry| entry.key == key)
            .count(),
        1
    );
}

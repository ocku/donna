//! Negative cache admission must describe the terminal CNAME owner.
use super::{tests::fixture, *};
use dns::{ClassType, DomainName, QueryType, ResourceRecord};

fn name(value: &str) -> DomainName {
    DomainName::from_dotted(value).unwrap()
}

fn soa(owner: &str, ttl: u32, minimum: u32) -> ResourceRecord {
    ResourceRecord {
        name: name(owner),
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl,
        rdata: RData::SOA {
            mname: name("ns.example.test"),
            rname: name("hostmaster.example.test"),
            serial: 1,
            refresh: 60,
            retry: 60,
            expire: 600,
            minimum,
        },
    }
}

fn cname_nodata() -> (Message, Message) {
    let (_, mut query, mut response) = fixture();
    query.questions[0].qname = name("alias.outside.test");
    response.questions = query.questions.clone();
    response.answers = vec![ResourceRecord {
        name: query.questions[0].qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 600,
        rdata: RData::CNAME(name("missing.example.test")),
    }];
    response.authorities = vec![soa("example.test", 600, 60)];
    (query, response)
}

#[test]
fn cname_nodata_respects_soa_minimum_ttl_and_negative_policy() {
    for (soa_ttl, minimum, cap, expected) in [(600, 1, 300, 1), (2, 600, 300, 2), (600, 600, 3, 3)]
    {
        let (mut forwarder, _, _) = fixture();
        forwarder.max_negative_ttl = cap;
        let (query, mut response) = cname_nodata();
        response.authorities = vec![soa("example.test", soa_ttl, minimum)];
        forwarder.remember(&query, &response);

        let cached = forwarder.cached(&query).unwrap();
        assert_eq!(cached.answers[0].ttl, expected);
        assert_eq!(cached.authorities[0].ttl, expected);
        let mut entries = forwarder.cache.lock().unwrap();
        let entry = entries.values_mut().next().unwrap();
        assert_eq!(entry.lifetime, Duration::from_secs(u64::from(expected)));
        entry.inserted -= entry.lifetime;
        drop(entries);
        assert!(forwarder.cached(&query).is_none());
    }
}

#[test]
fn cname_negative_requires_an_applicable_soa_and_acyclic_chain() {
    for rcode in [RCode::Ok, RCode::NameError] {
        for invalid in ["missing", "owner", "class", "cycle", "zero"] {
            let (forwarder, _, _) = fixture();
            let (query, mut response) = cname_nodata();
            response.headers.rcode = rcode;
            match invalid {
                "missing" => response.authorities.clear(),
                "owner" => response.authorities[0].name = name("outside.test"),
                "class" => response.authorities[0].class = ClassType::CH,
                "cycle" => {
                    response.answers[0].rdata = RData::CNAME(query.questions[0].qname.clone());
                }
                "zero" => response.authorities = vec![soa("example.test", 600, 0)],
                _ => unreachable!(),
            }
            forwarder.remember(&query, &response);
            assert!(forwarder.cached(&query).is_none(), "{rcode:?} {invalid}");
        }
    }
}

#[test]
fn positive_cname_answers_are_independent_of_negative_cache_policy() {
    for qtype in [QueryType::A, QueryType::CNAME, QueryType::ANY] {
        let (mut forwarder, _, mut positive) = fixture();
        forwarder.max_negative_ttl = 0;
        let (mut query, mut response) = cname_nodata();
        query.questions[0].qtype = qtype;
        response.questions = query.questions.clone();
        if qtype == QueryType::A {
            positive.answers[0].name = name("missing.example.test");
            response.answers.push(positive.answers.remove(0));
        }
        response.authorities.clear();
        forwarder.remember(&query, &response);
        assert!(forwarder.cached(&query).is_some(), "{qtype:?}");
    }
}

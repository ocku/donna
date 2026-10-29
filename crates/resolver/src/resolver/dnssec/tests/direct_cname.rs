use std::sync::Arc;

use dns::{
    ClassType, Headers, Message, QClassType, QueryType, Question, RData, RecordType, ResourceRecord,
};

use super::super::records::{is_negative, terminal_name};
use super::{
    fixtures::{resolver, signed_record_fixture},
    support::name,
};

#[tokio::test]
async fn signed_direct_cname_answers_are_secure_and_cached() {
    for qtype in [QueryType::CNAME, QueryType::ANY] {
        let target = name(&["target", "example"]);
        let (transport, anchor, question) = signed_record_fixture(
            false,
            name(&["alias", "example"]),
            qtype,
            RecordType::CNAME,
            RData::CNAME(target.clone()),
        );
        let requests = Arc::clone(&transport.requests);
        let resolver = resolver(transport, anchor);
        for _ in 0..2 {
            let response = resolver.resolve(question.clone()).await.unwrap();
            assert!(response.headers.ad, "{qtype:?}");
            assert!(response.answers.iter().any(|record| {
                record.name.eq_dns(&question.qname)
                    && matches!(&record.rdata, RData::CNAME(value) if value.eq_dns(&target))
            }));
        }
        assert_eq!(requests.lock().unwrap().len(), 2, "{qtype:?}");
    }
}

#[test]
fn negative_classification_and_cname_traversal_ignore_other_classes() {
    let question = Question {
        qname: name(&["alias", "example"]),
        qclass: QClassType::Class(ClassType::IN),
        qtype: QueryType::A,
    };
    let foreign = ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::CH,
        ttl: 300,
        rdata: RData::CNAME(name(&["target", "example"])),
    };
    assert!(terminal_name(&question, std::slice::from_ref(&foreign)).eq_dns(&question.qname));
    let response = Message {
        headers: Headers::default(),
        questions: vec![question.clone()],
        answers: vec![ResourceRecord {
            rtype: RecordType::A,
            rdata: RData::A(std::net::Ipv4Addr::LOCALHOST),
            ..foreign
        }],
        authorities: vec![],
        additionals: vec![],
    };
    assert!(is_negative(&response, &question));
}

//! Exercises a validated cached DNAME across real resolver state transitions.
use super::super::super::{
    fixtures::{resolver, signed_record_fixture},
    support::name,
};
use dns::{ClassType, Message, QClassType, QueryType, Question, RData, RecordType};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use transport::{BoxFuture, Transport, TransportError};

#[derive(Clone)]
pub(in crate::resolver::dnssec::tests::dname) struct Routed {
    pub(in crate::resolver::dnssec::tests::dname) source: Arc<Mutex<Message>>,
    pub(in crate::resolver::dnssec::tests::dname) targets: Vec<Message>,
    pub(in crate::resolver::dnssec::tests::dname) dnskey: Message,
    pub(in crate::resolver::dnssec::tests::dname) requests: Arc<Mutex<Vec<Question>>>,
    pub(in crate::resolver::dnssec::tests::dname) servers: Arc<Mutex<Vec<(SocketAddr, Question)>>>,
}

impl Transport for Routed {
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a Message,
        _timeout: Duration,
    ) -> BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            let q = &query.questions[0];
            self.requests.lock().unwrap().push(q.clone());
            self.servers.lock().unwrap().push((server, q.clone()));
            let mut reply = if q.qtype == QueryType::DNSKEY {
                self.dnskey.clone()
            } else if server.ip() == Ipv4Addr::new(192, 0, 2, 200) {
                self.targets
                    .iter()
                    .find(|message| message.questions[0].qname.eq_dns(&q.qname))
                    .expect("known delegated fixture")
                    .clone()
            } else if q.qname.is_descendant_of(&name(&["old", "example"])) {
                self.source.lock().unwrap().clone()
            } else {
                self.targets
                    .iter()
                    .find(|message| message.questions[0].qname.eq_dns(&q.qname))
                    .expect("known terminal fixture")
                    .clone()
            };
            reply.headers.id = query.headers.id;
            reply.questions = vec![q.clone()];
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn fresh_child_referral_vetoes_cached_ancestor_before_it_is_stored() {
    use crate::resolver::AlgorithmSignals;
    use std::sync::atomic::AtomicUsize;
    let (source, anchor, owner_question) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    let (mut alias, _, _) = signed_record_fixture(
        false,
        name(&["aliaschild", "example"]),
        QueryType::A,
        RecordType::CNAME,
        RData::CNAME(name(&["www", "child", "old", "example"])),
    );
    let child = name(&["child", "old", "example"]);
    let ns = name(&["ns", "child", "old", "example"]);
    alias.answer.authorities.push(dns::ResourceRecord {
        name: child,
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(ns.clone()),
    });
    alias.answer.additionals.push(dns::ResourceRecord {
        name: ns,
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 200)),
    });
    let (child_answer, _, _) = signed_record_fixture(
        false,
        name(&["www", "child", "old", "example"]),
        QueryType::A,
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 50)),
    );
    let servers = Arc::new(Mutex::new(Vec::new()));
    let transport = Routed {
        source: Arc::new(Mutex::new(source.answer.clone())),
        targets: vec![alias.answer, child_answer.answer],
        dnskey: source.dnskey,
        requests: Arc::new(Mutex::new(Vec::new())),
        servers: servers.clone(),
    };
    let resolver = resolver(transport, anchor);
    assert!(resolver.resolve(owner_question).await.unwrap().headers.ad);
    let question = Question {
        qname: name(&["aliaschild", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let outcome = resolver
        .resolve_inner(
            question,
            vec![],
            Arc::new(AtomicUsize::new(64)),
            None,
            Arc::new(AlgorithmSignals::default()),
            true,
        )
        .await
        .unwrap();
    assert!(
        outcome
            .response
            .answers
            .iter()
            .any(|rr| matches!(rr.rdata, RData::A(a) if a.octets() == [192, 0, 2, 50]))
    );
    assert!(
        !outcome
            .response
            .answers
            .iter()
            .any(|rr| rr.rtype == RecordType::DNAME)
    );
    assert!(
        servers
            .lock()
            .unwrap()
            .iter()
            .any(|(server, q)| server.ip() == Ipv4Addr::new(192, 0, 2, 200)
                && q.qname.eq_dns(&name(&["www", "child", "old", "example"])))
    );
}

#[tokio::test]
async fn secure_cached_dname_follows_target_then_refreshes_changed_target_after_expiry() {
    let (mut original, anchor, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    original.answer.answers[0].ttl = 4;
    let (changed, _, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["other", "example"])),
    );
    let target = |host: &'static str, zone: &'static str, byte| {
        signed_record_fixture(
            false,
            name(&[host, zone, "example"]),
            QueryType::A,
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, byte)),
        )
        .0
        .answer
    };
    let source = Arc::new(Mutex::new(original.answer.clone()));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut alias = signed_record_fixture(
        false,
        name(&["alias", "example"]),
        QueryType::A,
        RecordType::CNAME,
        RData::CNAME(name(&["second", "old", "example"])),
    )
    .0
    .answer;
    // The source may include a referral for the CNAME's original target.
    // After cached DNAME substitution that referral no longer covers the
    // active target and must not steer the next lookup.
    alias.authorities.push(dns::ResourceRecord {
        name: name(&["old", "example"]),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(name(&["ns", "old", "example"])),
    });
    alias.additionals.push(dns::ResourceRecord {
        name: name(&["ns", "old", "example"]),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 200)),
    });
    let mut referral_only = alias.clone();
    referral_only.answers.clear();
    referral_only.headers.aa = false;
    let referral_question = Question {
        qname: name(&["second", "old", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(crate::protocol::referral(&referral_only, &referral_question).is_some());
    let servers = Arc::new(Mutex::new(Vec::new()));
    let transport = Routed {
        source: source.clone(),
        targets: vec![
            target("first", "new", 1),
            target("second", "new", 2),
            target("second", "other", 3),
            alias,
        ],
        dnskey: original.dnskey,
        requests: requests.clone(),
        servers: servers.clone(),
    };
    let resolver = resolver(transport, anchor);
    let question = |host| Question {
        qname: name(&[host, "old", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let first = resolver.resolve(question("first")).await.unwrap();
    assert!(first.headers.ad);
    assert!(
        first
            .answers
            .iter()
            .any(|rr| matches!(rr.rdata, RData::A(a) if a.octets() == [192, 0, 2, 1]))
    );
    *source.lock().unwrap() = changed.answer;
    let alias_question = Question {
        qname: name(&["alias", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let before = requests.lock().unwrap().len();
    let before_servers = servers.lock().unwrap().len();
    let alias_response = resolver.resolve(alias_question.clone()).await.unwrap();
    assert!(alias_response.headers.ad);
    assert!(
        alias_response
            .answers
            .iter()
            .any(|rr| matches!(rr.rdata, RData::A(a) if a.octets() == [192, 0, 2, 2]))
    );
    assert!(
        requests.lock().unwrap()[before..]
            .iter()
            .any(|q| q.qname.eq_dns(&alias_question.qname))
    );
    assert!(
        !requests.lock().unwrap()[before..]
            .iter()
            .any(|q| q.qname.eq_dns(&question("second").qname)),
        "cached DNAME should apply after a network CNAME"
    );
    assert!(
        servers.lock().unwrap()[before_servers..]
            .iter()
            .any(|(server, q)| {
                q.qname.eq_dns(&name(&["second", "new", "example"]))
                    && server.ip() == Ipv4Addr::LOCALHOST
            }),
        "the stale referral must not direct the new DNAME target"
    );
    let before = requests.lock().unwrap().len();
    let second = resolver.resolve(question("second")).await.unwrap();
    assert!(second.headers.ad);
    assert!(
        second
            .answers
            .iter()
            .any(|rr| matches!(rr.rdata, RData::A(a) if a.octets() == [192, 0, 2, 2]))
    );
    assert!(
        !requests.lock().unwrap()[before..]
            .iter()
            .any(|q| q.qname.eq_dns(&question("second").qname))
    );
    tokio::time::sleep(Duration::from_millis(4100)).await;
    let before = requests.lock().unwrap().len();
    let refreshed = resolver.resolve(question("second")).await.unwrap();
    assert!(refreshed.headers.ad);
    assert!(
        refreshed
            .answers
            .iter()
            .any(|rr| matches!(rr.rdata, RData::A(a) if a.octets() == [192, 0, 2, 3]))
    );
    assert!(
        requests.lock().unwrap()[before..]
            .iter()
            .any(|q| q.qname.eq_dns(&question("second").qname))
    );
}

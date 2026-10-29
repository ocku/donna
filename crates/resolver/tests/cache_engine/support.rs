use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord,
};
use resolver::ResolverConfig;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use transport::{Transport, TransportError, TransportProtocol};

#[derive(Clone, Default)]
pub struct Authority {
    pub requests: Arc<Mutex<Vec<Question>>>,
    pub ttl: Arc<AtomicU32>,
}

pub fn name(text: &str) -> DomainName {
    DomainName::from_labels(
        text.split('.')
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

pub fn question(text: &str) -> Question {
    Question {
        qname: name(text),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

pub fn config() -> ResolverConfig {
    ResolverConfig {
        root_servers: vec!["192.0.2.53:53".parse().unwrap()],
        max_attempts_per_server: 1,
        cache_capacity: 128,
        ..ResolverConfig::default()
    }
}

impl Transport for Authority {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            let q = query.questions[0].clone();
            self.requests.lock().unwrap().push(q.clone());
            let negative = q
                .qname
                .as_ref()
                .first()
                .is_some_and(|l| l.as_slice() == b"missing");
            let ttl = self.ttl.load(Ordering::Relaxed);
            let ttl = if ttl == 0 { 300 } else { ttl };
            let mut answer = ResourceRecord {
                name: q.qname.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 8)),
            };
            if q.qname == name("alias.example") {
                answer.rtype = RecordType::CNAME;
                answer.rdata = RData::CNAME(name("www.example"));
            }
            let soa = ResourceRecord {
                name: name("example"),
                rtype: RecordType::SOA,
                class: ClassType::IN,
                ttl,
                rdata: RData::SOA {
                    mname: name("ns.example"),
                    rname: name("hostmaster.example"),
                    serial: 1,
                    refresh: 300,
                    retry: 60,
                    expire: 3600,
                    minimum: ttl,
                },
            };
            Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    rcode: if negative {
                        RCode::NameError
                    } else {
                        RCode::Ok
                    },
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: if negative { vec![] } else { vec![answer] },
                authorities: if negative { vec![soa] } else { vec![] },
                additionals: vec![],
            })
        })
    }
}

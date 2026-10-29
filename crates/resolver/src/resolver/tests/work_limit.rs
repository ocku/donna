use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, atomic::AtomicUsize},
    time::Duration,
};

use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use transport::{Transport, TransportError};

use super::{AlgorithmSignals, Resolver};
use crate::ResolverConfig;

#[derive(Clone, Copy)]
struct NoIo;

impl Transport for NoIo {
    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        _query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move { panic!("work continued after the resolver budget was exhausted") })
    }
}

#[tokio::test]
async fn exhausted_budget_does_not_start_name_server_address_lookups() {
    let resolver = Resolver::new(NoIo, ResolverConfig::default());
    let name_server = DomainName::from_labels(vec![b"ns".to_vec(), b"example".to_vec()]).unwrap();

    let resolution = resolver
        .resolve_name_server_addresses(
            &[name_server],
            &[],
            std::sync::Arc::new(AtomicUsize::new(0)),
            None,
            std::sync::Arc::new(AlgorithmSignals::default()),
        )
        .await;

    assert!(resolution.addresses.is_empty());
    assert!(resolution.pending_name_servers.is_empty());
}

#[derive(Clone)]
struct CorrelationTransport {
    mismatching_server: SocketAddr,
    udp_calls: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Transport for CorrelationTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.udp_calls.lock().unwrap().push(server);
            let mismatched = server == self.mismatching_server;
            Ok(Message {
                headers: Headers {
                    id: query.headers.id.wrapping_add(u16::from(mismatched)),
                    qr: true,
                    aa: !mismatched,
                    tc: mismatched,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: (!mismatched)
                    .then(|| ResourceRecord {
                        name: query.questions[0].qname.clone(),
                        rtype: RecordType::A,
                        class: ClassType::IN,
                        ttl: 60,
                        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    })
                    .into_iter()
                    .collect(),
                authorities: Vec::new(),
                additionals: Vec::new(),
            })
        })
    }
}

#[tokio::test]
async fn truncation_is_acted_on_only_after_response_correlation() {
    let good_server = "192.0.2.1:53".parse().unwrap();
    let mismatching_server = "192.0.2.2:53".parse().unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::new(
        CorrelationTransport {
            mismatching_server,
            udp_calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![good_server, mismatching_server],
            max_steps: 2,
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let qname = DomainName::from_labels(vec![b"www".to_vec(), b"example".to_vec()]).unwrap();

    let reply = resolver
        .resolve(Question {
            qname,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();

    assert_eq!(*calls.lock().unwrap(), [mismatching_server, good_server]);
    assert!(matches!(reply.answers[0].rdata, RData::A(_)));
}

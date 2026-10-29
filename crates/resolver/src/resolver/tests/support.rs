use std::{
    future::poll_fn,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use dns::{
    Caa, ClassType, DomainName, Ds, FromWire, Headers, IntoWire, Message, QClassType, QueryType,
    Question, RCode, RData, RecordType, ResourceRecord,
};
use transport::{TransitionReason, Transport, TransportError, TransportProtocol, TransportRoute};

use super::Resolver;
use crate::response::{delegation_progresses, query_type_matches_record};
use crate::{ResolutionCacheSource, ResolveError, ResolverConfig};

#[derive(Clone)]
struct MockTransport {
    replies: Arc<Mutex<Vec<Message>>>,
    requests: Arc<Mutex<Vec<Message>>>,
}

#[derive(Clone)]
struct EdnsUnawareTransport {
    requests: Arc<Mutex<Vec<Message>>>,
    sends_opt_after_fallback: bool,
}


impl Transport for EdnsUnawareTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        self.requests.lock().unwrap().push(query.clone());
        if query.edns().unwrap().is_some() {
            return Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    rcode: RCode::FormatError,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
            });
        }
        Ok(Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: true,
                ..Headers::default()
            },
            questions: query.questions.clone(),
            answers: vec![address_record(query.questions[0].qname.clone(), 1)],
            authorities: Vec::new(),
            additionals: self
                .sends_opt_after_fallback
                .then(|| dns::Edns::new(1232).into_record())
                .into_iter()
                .collect(),
        })
    }) }
}


impl Transport for MockTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        self.requests.lock().unwrap().push(query.clone());
        let mut reply = self.replies.lock().unwrap().remove(0);
        if reply.headers.id == 0 {
            reply.headers.id = query.headers.id;
        }
        if reply.questions.is_empty() {
            reply.questions = query.questions.clone();
        }
        Ok(reply)
    }) }
}

#[derive(Clone)]
struct TruncatingTransport {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

#[derive(Clone)]
struct CompletingTransport {
    calls: Arc<Mutex<Vec<&'static str>>>,
    tcp_truncated: bool,
}

enum RoutedOutcome {
    Timeout,
    IoError,
    Complete,
}

struct RoutedTestTransport {
    name: &'static str,
    protocol: Option<TransportProtocol>,
    outcome: RoutedOutcome,
    calls: Arc<Mutex<Vec<&'static str>>>,
}


impl Transport for TruncatingTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        self.calls.lock().unwrap().push("udp");
        let mut reply = response(
            Headers {
                id: query.headers.id,
                qr: true,
                tc: true,
                ..Headers::default()
            },
            Vec::new(),
        );
        reply.questions = query.questions.clone();
        Ok(reply)
    }) }
}


impl Transport for CompletingTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Tcp)
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        self.calls.lock().unwrap().push("tcp");
        let mut reply = response(
            Headers {
                id: query.headers.id,
                qr: true,
                aa: true,
                tc: self.tcp_truncated,
                ..Headers::default()
            },
            vec![address_record(query.questions[0].qname.clone(), 1)],
        );
        // TCP may omit the question on the wire, but the transport normalizes
        // the correlated response before returning it to the resolver.
        reply.questions.clone_from(&query.questions);
        Ok(reply)
    }) }
}


impl Transport for RoutedTestTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        self.protocol
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        self.calls.lock().unwrap().push(self.name);
        match self.outcome {
            RoutedOutcome::Timeout => Err(TransportError::Timeout),
            RoutedOutcome::IoError => Err(TransportError::Io(std::io::Error::other("unavailable"))),
            RoutedOutcome::Complete => {
                let mut reply = response(
                    Headers {
                        id: query.headers.id,
                        qr: true,
                        aa: true,
                        ..Headers::default()
                    },
                    vec![address_record(query.questions[0].qname.clone(), 1)],
                );
                reply.questions.clone_from(&query.questions);
                Ok(reply)
            }
        }
    }) }
}

fn truncation_route(calls: Arc<Mutex<Vec<&'static str>>>, tcp_truncated: bool) -> TransportRoute {
    TransportRoute::new(TruncatingTransport {
        calls: Arc::clone(&calls),
    })
    .on(
        [
            TransitionReason::QueryTooLarge,
            TransitionReason::TruncatedResponse,
        ],
        CompletingTransport {
            calls: Arc::clone(&calls),
            tcp_truncated,
        },
    )
}

#[derive(Clone)]
struct RetryTransport {
    attempts: Arc<Mutex<u8>>,
    reply: Message,
}

#[derive(Clone)]
struct TcpRetryTransport {
    calls: Arc<Mutex<u8>>,
    reply: Message,
}


impl Transport for RetryTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        let mut attempts = self.attempts.lock().unwrap();
        *attempts += 1;
        if *attempts == 1 {
            return Err(TransportError::Timeout);
        }
        let mut reply = self.reply.clone();
        reply.headers.id = query.headers.id;
        reply.questions = query.questions.clone();
        Ok(reply)
    }) }
}


impl Transport for TcpRetryTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Tcp)
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        if *calls == 1 {
            return Err(TransportError::Timeout);
        }
        let mut reply = self.reply.clone();
        reply.headers.id = query.headers.id;
        reply.questions.clone_from(&query.questions);
        Ok(reply)
    }) }
}

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn question(labels: &[&str]) -> Question {
    Question {
        qname: name(labels),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn response(headers: Headers, answers: Vec<ResourceRecord>) -> Message {
    Message {
        headers,
        questions: Vec::new(),
        answers,
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn config(servers: Vec<SocketAddr>) -> ResolverConfig {
    ResolverConfig {
        root_servers: servers,
        max_steps: 8,
        ..ResolverConfig::default()
    }
}

fn address_record(owner: DomainName, last_octet: u8) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
    }
}

fn cname_record(owner: DomainName, target: DomainName) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(target),
    }
}

fn soa_record(zone: DomainName, ttl: u32, minimum: u32) -> ResourceRecord {
    ResourceRecord {
        name: zone,
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl,
        rdata: RData::SOA {
            mname: name(&["ns", "example"]),
            rname: name(&["hostmaster", "example"]),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum,
        },
    }
}

/// Replies instantly for every server except `slow_server`, which delays; each
/// server's answer carries its own distinguishable address.
#[derive(Clone)]
struct RacingTransport {
    slow_server: SocketAddr,
    delay: Duration,
}


impl Transport for RacingTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        if server == self.slow_server {
            tokio::time::sleep(self.delay).await;
        }
        let last_octet = if server == self.slow_server { 1 } else { 2 };
        let mut reply = response(
            Headers {
                id: query.headers.id,
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.questions[0].qname.clone(), last_octet)],
        );
        reply.questions = query.questions.clone();
        Ok(reply)
    }) }
}

fn referral_response(zone: DomainName, name_server: DomainName, last_octet: u8) -> Message {
    Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: zone,
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::NS(name_server.clone()),
        }],
        additionals: vec![address_record(name_server, last_octet)],
    }
}

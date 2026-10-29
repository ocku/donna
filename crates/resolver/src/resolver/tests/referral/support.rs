use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, atomic::AtomicUsize},
    time::Duration,
};

use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use transport::{Transport, TransportError, TransportProtocol};

use super::{AlgorithmSignals, Resolver};
use crate::ResolverConfig;

#[derive(Clone)]
struct RoutedTransport {
    root: SocketAddr,
    authority: SocketAddr,
    alias: DomainName,
    target: DomainName,
    name_server: DomainName,
    calls: Arc<Mutex<Vec<SocketAddr>>>,
}

#[derive(Clone)]
struct OutOfBailiwickGlueTransport {
    root: SocketAddr,
    attacker: SocketAddr,
    authority: SocketAddr,
    delegated_zone: DomainName,
    target: DomainName,
    name_server: DomainName,
    calls: Arc<Mutex<Vec<SocketAddr>>>,
}

#[derive(Clone)]
struct RootSiblingGlueTransport {
    root: SocketAddr,
    com_server: SocketAddr,
    name_server: DomainName,
    calls: Arc<Mutex<Vec<(SocketAddr, DomainName, QueryType)>>>,
}

#[derive(Clone)]
struct ExactInBailiwickGlueTransport {
    root: SocketAddr,
    ipv4_glue: SocketAddr,
    ipv6_glue: SocketAddr,
    delegated_zone: DomainName,
    name_server: DomainName,
    calls: Arc<Mutex<Vec<(SocketAddr, DomainName, QueryType)>>>,
}

#[derive(Clone)]
struct LazyGluelessTransport {
    root: SocketAddr,
    dead: SocketAddr,
    authority: SocketAddr,
    delegated_zone: DomainName,
    target: DomainName,
    name_servers: Vec<DomainName>,
    empty_name_server: Option<DomainName>,
    dead_name_server: DomainName,
    working_name_server: DomainName,
    calls: Arc<Mutex<Vec<(SocketAddr, DomainName, QueryType)>>>,
}


impl Transport for RoutedTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        self.calls.lock().unwrap().push(server);
        let question = &query.questions[0];
        let (answers, authorities, additionals) =
            if server == self.root && question.qname.eq_dns(&self.alias) {
                (
                    vec![record(
                        self.alias.clone(),
                        RecordType::CNAME,
                        RData::CNAME(self.target.clone()),
                    )],
                    vec![record(
                        name(&["other"]),
                        RecordType::NS,
                        RData::NS(self.name_server.clone()),
                    )],
                    vec![record(
                        self.name_server.clone(),
                        RecordType::A,
                        RData::A(match self.authority.ip() {
                            std::net::IpAddr::V4(address) => address,
                            std::net::IpAddr::V6(_) => unreachable!(),
                        }),
                    )],
                )
            } else if server == self.authority && question.qname.eq_dns(&self.target) {
                (
                    vec![record(
                        self.target.clone(),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 80)),
                    )],
                    Vec::new(),
                    Vec::new(),
                )
            } else {
                panic!("query did not follow the CNAME target referral")
            };
        Ok(Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: server == self.authority,
                ..Headers::default()
            },
            questions: query.questions.clone(),
            answers,
            authorities,
            additionals,
        })
    }) }
}


impl Transport for OutOfBailiwickGlueTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        self.calls.lock().unwrap().push(server);
        let question = &query.questions[0];
        if server == self.attacker && question.qname.eq_dns(&self.target) {
            return Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: vec![record(
                    self.target.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(203, 0, 113, 66)),
                )],
                authorities: Vec::new(),
                additionals: Vec::new(),
            });
        }
        let (authoritative, answers, authorities, additionals) =
            if server == self.root && question.qname.eq_dns(&self.target) {
                (
                    false,
                    Vec::new(),
                    vec![record(
                        self.delegated_zone.clone(),
                        RecordType::NS,
                        RData::NS(self.name_server.clone()),
                    )],
                    vec![record(
                        name(&["unrelated", "provider"]),
                        RecordType::A,
                        RData::A(match self.attacker.ip() {
                            std::net::IpAddr::V4(address) => address,
                            std::net::IpAddr::V6(_) => unreachable!(),
                        }),
                    )],
                )
            } else if server == self.root
                && question.qname.eq_dns(&self.name_server)
                && question.qtype == QueryType::A
            {
                (
                    true,
                    vec![record(
                        self.name_server.clone(),
                        RecordType::A,
                        RData::A(match self.authority.ip() {
                            std::net::IpAddr::V4(address) => address,
                            std::net::IpAddr::V6(_) => unreachable!(),
                        }),
                    )],
                    Vec::new(),
                    Vec::new(),
                )
            } else if server == self.root
                && question.qname.eq_dns(&self.name_server)
                && question.qtype == QueryType::AAAA
            {
                (
                    true,
                    Vec::new(),
                    vec![record(
                        name(&["provider"]),
                        RecordType::SOA,
                        RData::SOA {
                            mname: self.name_server.clone(),
                            rname: name(&["hostmaster", "provider"]),
                            serial: 1,
                            refresh: 2,
                            retry: 3,
                            expire: 4,
                            minimum: 30,
                        },
                    )],
                    Vec::new(),
                )
            } else if server == self.authority && question.qname.eq_dns(&self.target) {
                (
                    true,
                    vec![record(
                        self.target.clone(),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 80)),
                    )],
                    Vec::new(),
                    Vec::new(),
                )
            } else {
                panic!("unexpected referral test query to {server} for {question:?}")
            };

        Ok(Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: authoritative,
                ..Headers::default()
            },
            questions: query.questions.clone(),
            answers,
            authorities,
            additionals,
        })
    }) }
}


impl Transport for RootSiblingGlueTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        let question = &query.questions[0];
        self.calls
            .lock()
            .unwrap()
            .push((server, question.qname.clone(), question.qtype));

        let (authoritative, answers, authorities, additionals) = if server == self.root
            && question.qname.is_descendant_of(&name(&["com"]))
        {
            let std::net::IpAddr::V4(address) = self.com_server.ip() else {
                unreachable!("the modeled .com server is IPv4")
            };
            (
                false,
                Vec::new(),
                vec![record(
                    name(&["com"]),
                    RecordType::NS,
                    RData::NS(self.name_server.clone()),
                )],
                vec![record(
                    self.name_server.clone(),
                    RecordType::A,
                    RData::A(address),
                )],
            )
        } else if server == self.com_server && question.qname.is_descendant_of(&name(&["com"])) {
            (
                true,
                vec![record(
                    question.qname.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 80)),
                )],
                Vec::new(),
                Vec::new(),
            )
        } else {
            panic!("unexpected sibling-glue query to {server} for {question:?}")
        };

        Ok(Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: authoritative,
                ..Headers::default()
            },
            questions: query.questions.clone(),
            answers,
            authorities,
            additionals,
        })
    }) }
}


impl Transport for ExactInBailiwickGlueTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        let question = &query.questions[0];
        self.calls
            .lock()
            .unwrap()
            .push((server, question.qname.clone(), question.qtype));

        let (authoritative, answers, authorities, additionals) =
            if server == self.root && question.qname.eq_dns(&self.name_server) {
                let std::net::IpAddr::V4(ipv4) = self.ipv4_glue.ip() else {
                    unreachable!("the IPv4 glue address is IPv4")
                };
                let std::net::IpAddr::V6(ipv6) = self.ipv6_glue.ip() else {
                    unreachable!("the IPv6 glue address is IPv6")
                };
                (
                    false,
                    Vec::new(),
                    vec![record(
                        self.delegated_zone.clone(),
                        RecordType::NS,
                        RData::NS(self.name_server.clone()),
                    )],
                    vec![
                        record(self.name_server.clone(), RecordType::A, RData::A(ipv4)),
                        record(
                            self.name_server.clone(),
                            RecordType::AAAA,
                            RData::AAAA(ipv6),
                        ),
                    ],
                )
            } else if (server == self.ipv4_glue || server == self.ipv6_glue)
                && question.qname.eq_dns(&self.name_server)
                && question.qtype == QueryType::A
            {
                (
                    true,
                    vec![record(
                        self.name_server.clone(),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 80)),
                    )],
                    Vec::new(),
                    Vec::new(),
                )
            } else {
                panic!("unexpected exact-glue query to {server} for {question:?}")
            };

        Ok(Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: authoritative,
                ..Headers::default()
            },
            questions: query.questions.clone(),
            answers,
            authorities,
            additionals,
        })
    }) }
}


impl Transport for LazyGluelessTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        let question = &query.questions[0];
        self.calls
            .lock()
            .unwrap()
            .push((server, question.qname.clone(), question.qtype));

        if server == self.dead && question.qname.eq_dns(&self.target) {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "name server is unreachable",
            )));
        }

        let (authoritative, answers, authorities) =
            if server == self.root && question.qname.eq_dns(&self.target) {
                (
                    false,
                    Vec::new(),
                    self.name_servers
                        .iter()
                        .map(|name_server| {
                            record(
                                self.delegated_zone.clone(),
                                RecordType::NS,
                                RData::NS(name_server.clone()),
                            )
                        })
                        .collect(),
                )
            } else if server == self.root
                && self
                    .name_servers
                    .iter()
                    .any(|name_server| name_server.eq_dns(&question.qname))
            {
                let answers = if question.qtype == QueryType::A
                    && question.qname.eq_dns(&self.dead_name_server)
                {
                    vec![record(
                        question.qname.clone(),
                        RecordType::A,
                        RData::A(match self.dead.ip() {
                            std::net::IpAddr::V4(address) => address,
                            std::net::IpAddr::V6(_) => unreachable!(),
                        }),
                    )]
                } else if question.qtype == QueryType::A
                    && question.qname.eq_dns(&self.working_name_server)
                {
                    vec![record(
                        question.qname.clone(),
                        RecordType::A,
                        RData::A(match self.authority.ip() {
                            std::net::IpAddr::V4(address) => address,
                            std::net::IpAddr::V6(_) => unreachable!(),
                        }),
                    )]
                } else {
                    Vec::new()
                };
                (true, answers, Vec::new())
            } else if server == self.authority && question.qname.eq_dns(&self.target) {
                (
                    true,
                    vec![record(
                        self.target.clone(),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 80)),
                    )],
                    Vec::new(),
                )
            } else {
                panic!("unexpected glueless referral query to {server} for {question:?}")
            };

        if let Some(empty_name_server) = &self.empty_name_server
            && question.qname.eq_dns(empty_name_server)
        {
            assert!(answers.is_empty());
        }

        Ok(Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: authoritative,
                ..Headers::default()
            },
            questions: query.questions.clone(),
            answers,
            authorities,
            additionals: Vec::new(),
        })
    }) }
}

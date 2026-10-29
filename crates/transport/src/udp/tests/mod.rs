use std::{
    future::pending,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use dns::{
    ClassType, DomainName, Edns, EdnsOption, Headers, OpCode, QClassType, QueryType, Question,
    RCode, RData, RecordType, ResourceRecord,
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, Semaphore},
};

use super::*;
use crate::{
    DnsRequest, DnsRequestHandler, TransportServer, format_error_response_with_limit,
    recover_questions_from_edns_request, truncate_response,
};

struct StatefulUdpHandler {
    peer: SocketAddr,
}

fn padded_opt() -> ResourceRecord {
    let mut edns = Edns::new(1232);
    edns.options = vec![EdnsOption::padding_with_data(vec![0xff])];
    edns.into_record()
}

fn malformed_edns_query() -> (Message, Vec<u8>) {
    malformed_edns_query_with_questions(1, 1232)
}

fn query_with_question_codes(qtype: u16, qclass: u16) -> Vec<u8> {
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let mut packet = query.into_wire().unwrap();
    let question_codes = packet.len() - 4;
    packet[question_codes..question_codes + 2].copy_from_slice(&qtype.to_be_bytes());
    packet[question_codes + 2..].copy_from_slice(&qclass.to_be_bytes());
    packet
}

fn unrelated_formerr() -> Message {
    Message::builder()
        .headers(Headers {
            qr: true,
            rcode: RCode::FormatError,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"unrelated".to_vec()]).unwrap(),
            qtype: QueryType::AAAA,
            qclass: QClassType::Class(ClassType::CH),
        }])
        .build()
        .unwrap()
}

fn malformed_edns_query_with_questions(
    question_count: usize,
    udp_payload_size: u16,
) -> (Message, Vec<u8>) {
    let questions = (0..question_count)
        .map(|index| Question {
            qname: DomainName::from_labels(vec![format!("question-{index}").into_bytes()]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .collect::<Vec<_>>();
    let query = Message::builder()
        .headers(Headers {
            id: 0x1234,
            opcode: OpCode::Status,
            rd: true,
            ..Headers::default()
        })
        .questions(questions)
        .additionals([Edns::new(udp_payload_size).into_record()])
        .build()
        .unwrap();
    let mut packet = query.clone().into_wire().unwrap();
    let rdlength = packet.len() - 2;
    packet[rdlength..].copy_from_slice(&4_u16.to_be_bytes());
    packet.extend_from_slice(&[0, 15, 0, 1]);
    (query, packet)
}

fn test_server_policy(packet_limit: usize) -> UdpServerPolicy {
    UdpServerPolicy {
        packet_limit,
        handler_reply_timeout: Duration::from_secs(10),
        response_send_timeout: Duration::from_secs(10),
    }
}

struct HandlerActivityGuard(Arc<AtomicUsize>);

impl Drop for HandlerActivityGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct BlockingUdpHandler {
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    releases: Arc<Semaphore>,
}

impl DnsRequestHandler for BlockingUdpHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            let _active = HandlerActivityGuard(Arc::clone(&self.active));
            self.entered.notify_one();
            self.releases.acquire().await.unwrap().forget();
            let _ = request.respond(Message::builder().build().unwrap());
        })
    }
}

struct FirstRequestPendingHandler {
    entered: Arc<Notify>,
    active: Arc<AtomicUsize>,
}

impl DnsRequestHandler for FirstRequestPendingHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = HandlerActivityGuard(Arc::clone(&self.active));
            self.entered.notify_one();
            if request.message().headers.id == 1 {
                pending::<()>().await;
            }
            let _ = request.respond(Message::builder().build().unwrap());
        })
    }
}

fn udp_query(id: u16) -> Vec<u8> {
    Message::builder()
        .headers(Headers {
            id,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
        .into_wire()
        .unwrap()
}

fn ixfr_soa(serial: u32) -> ResourceRecord {
    let apex = DomainName::from_labels(vec![b"example".to_vec()]).unwrap();
    ResourceRecord {
        name: apex.clone(),
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl: 300,
        rdata: RData::SOA {
            mname: DomainName::from_labels(vec![b"ns".to_vec(), b"example".to_vec()]).unwrap(),
            rname: DomainName::from_labels(vec![b"hostmaster".to_vec(), b"example".to_vec()])
                .unwrap(),
            serial,
            refresh: 3600,
            retry: 600,
            expire: 86_400,
            minimum: 300,
        },
    }
}

fn ixfr_query() -> Message {
    Message::builder()
        .headers(Headers {
            id: 0x1995,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::IXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .authorities([ixfr_soa(1)])
        .build()
        .unwrap()
}

async fn receive_udp_message(socket: &UdpSocket) -> Message {
    let mut buffer = [0_u8; MAX_EDNS_UDP_MESSAGE_OCTETS];
    let length = socket.recv(&mut buffer).await.unwrap();
    Message::from_wire(&buffer[..length]).unwrap()
}

mod client;
mod concurrency;
mod exchange_and_transfer;
mod server_responses;
mod support;
mod truncated_client;
mod truncation;

use support::oversized_response;

mod immediate;
mod signed_responses;

mod prepared;

use std::{
    future::pending,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use dns::{ClassType, Headers, QClassType, QueryType, Question, RData, RecordType, ResourceRecord};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::{Notify, mpsc},
};

use super::{
    axfr::{
        RrsetKey, prepare_transfer_request, same_resource_record, validate_transfer_message,
        validate_transfer_record,
    },
    *,
};
use crate::MAX_UDP_MESSAGE_OCTETS;

fn soa(serial: u32) -> ResourceRecord {
    ResourceRecord {
        name: dns::DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::SOA,
        class: dns::ClassType::IN,
        ttl: 60,
        rdata: RData::SOA {
            mname: dns::DomainName::root(),
            rname: dns::DomainName::root(),
            serial,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
        },
    }
}

fn query(id: u16) -> Message {
    Message::builder()
        .headers(Headers {
            id,
            ..Headers::default()
        })
        .questions([Question {
            qname: dns::DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

fn malformed_edns_query() -> (Message, Vec<u8>) {
    malformed_edns_query_with_questions(1, 1232)
}

fn query_with_question_codes(qtype: u16, qclass: u16) -> Vec<u8> {
    let mut packet = query(42).into_wire().unwrap();
    let question_codes = packet.len() - 4;
    packet[question_codes..question_codes + 2].copy_from_slice(&qtype.to_be_bytes());
    packet[question_codes + 2..].copy_from_slice(&qclass.to_be_bytes());
    packet
}

fn unrelated_formerr() -> Message {
    Message::builder()
        .headers(Headers {
            qr: true,
            rcode: dns::RCode::FormatError,
            ..Headers::default()
        })
        .questions([Question {
            qname: dns::DomainName::from_labels(vec![b"unrelated".to_vec()]).unwrap(),
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
            qname: dns::DomainName::from_labels(vec![format!("question-{index}").into_bytes()])
                .unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .collect::<Vec<_>>();
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions(questions)
        .additionals([dns::Edns::new(udp_payload_size).into_record()])
        .build()
        .unwrap();
    let mut packet = query.clone().into_wire().unwrap();
    let rdlength = packet.len() - 2;
    packet[rdlength..].copy_from_slice(&4_u16.to_be_bytes());
    packet.extend_from_slice(&[0, 15, 0, 1]);
    (query, packet)
}

fn response_for(query: &Message, id: u16) -> Message {
    Message {
        headers: Headers {
            id,
            qr: true,
            opcode: query.headers.opcode,
            ..Headers::default()
        },
        questions: query.questions.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn badvers_response_for(query: &Message, id: u16) -> Message {
    let mut response = response_for(query, id);
    response.additionals.push(
        dns::Edns {
            extended_rcode: 1,
            version: dns::Edns::VERSION,
            ..dns::Edns::default()
        }
        .into_record(),
    );
    response
}

fn successful_axfr_response_for(query: &Message) -> Message {
    let mut response = response_for(query, query.headers.id);
    response.headers.aa = true;
    response.answers = vec![soa(1), soa(1)];
    response
}

#[test]
fn validates_single_message_ixfr_current_incremental_and_full_forms() {
    let mut request = query(1995);
    request.questions[0].qtype = QueryType::IXFR;
    request.authorities.push(soa(1));
    let mut response = response_for(&request, request.headers.id);
    response.headers.aa = true;

    response.answers = vec![soa(2)];
    assert!(valid_ixfr_response(&response, &request));

    response.answers = vec![soa(2), soa(1), a_record(), soa(2), a_record(), soa(2)];
    assert!(valid_ixfr_response(&response, &request));

    response.answers = vec![soa(2), a_record(), soa(2)];
    assert!(valid_ixfr_response(&response, &request));

    response.answers = vec![soa(2), soa(0), soa(2), soa(2)];
    assert!(!valid_ixfr_response(&response, &request));
    response.answers = vec![soa(2), soa(1), soa(1), soa(2)];
    assert!(!valid_ixfr_response(&response, &request));
    response.answers = vec![soa(2), soa(1), soa(2)];
    assert!(!valid_ixfr_response(&response, &request));
}

fn assert_malformed_axfr_edns_is_rejected(query: &Message, response: &Message) {
    assert!(matches!(
        validate_transfer_message(response, query, true),
        Err(TransportError::InvalidTransfer(
            "AXFR response contains malformed EDNS"
        ))
    ));
    assert!(!valid_axfr_response_series(
        std::slice::from_ref(response),
        &query.questions[0],
        true,
    ));
}

struct FixedTcpResponses(Vec<Message>);

impl DnsRequestHandler for FixedTcpResponses {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let _ = request.respond_all(self.0.clone());
        })
    }
}

struct StreamingTcpResponses(Vec<Message>);

impl DnsRequestHandler for StreamingTcpResponses {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let (responses, receiver) = mpsc::channel(1);
            if !request.respond_stream(receiver) {
                return;
            }
            for response in self.0.clone() {
                if responses.send(response).await.is_err() {
                    return;
                }
            }
        })
    }
}

struct StreamingProducerGuard(Arc<AtomicBool>);

impl Drop for StreamingProducerGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct RepeatingAxfrHandler {
    first: Message,
    subsequent: Message,
    cancelled: Arc<AtomicBool>,
}

impl DnsRequestHandler for RepeatingAxfrHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let (responses, receiver) = mpsc::channel(1);
            if !request.respond_stream(receiver) {
                return;
            }
            let _guard = StreamingProducerGuard(Arc::clone(&self.cancelled));
            if responses.send(self.first.clone()).await.is_err() {
                return;
            }
            loop {
                if responses.send(self.subsequent.clone()).await.is_err() {
                    return;
                }
            }
        })
    }
}

struct InvalidThenRepeatingAxfrHandler {
    first: Message,
    invalid: Message,
    subsequent: Message,
    cancelled: Arc<AtomicBool>,
}

impl DnsRequestHandler for InvalidThenRepeatingAxfrHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let (responses, receiver) = mpsc::channel(1);
            if !request.respond_stream(receiver) {
                return;
            }
            let _guard = StreamingProducerGuard(Arc::clone(&self.cancelled));
            for response in [self.first.clone(), self.invalid.clone()] {
                if responses.send(response).await.is_err() {
                    return;
                }
            }
            loop {
                if responses.send(self.subsequent.clone()).await.is_err() {
                    return;
                }
            }
        })
    }
}

struct CountingTcpHandler {
    calls: Arc<AtomicUsize>,
}

impl DnsRequestHandler for CountingTcpHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ = request.respond(Message::builder().build().unwrap());
        })
    }
}

struct PendingTcpHandler {
    entered: Arc<Notify>,
}

impl DnsRequestHandler for PendingTcpHandler {
    fn handle<'future>(&'future self, _request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            self.entered.notify_one();
            pending::<()>().await;
        })
    }
}

struct DelayedResponseThenPendingHandler {
    delay: Duration,
}

impl DnsRequestHandler for DelayedResponseThenPendingHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            time::sleep(self.delay).await;
            let _ = request.respond(Message::builder().build().unwrap());
            pending::<()>().await;
        })
    }
}

struct ResponseThenPanicHandler;

impl DnsRequestHandler for ResponseThenPanicHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let _ = request.respond(Message::builder().build().unwrap());
            panic!("handler panic after response");
        })
    }
}

struct ConditionalTcpHandler;

impl DnsRequestHandler for ConditionalTcpHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            if request.message().headers.id != 99 {
                let _ = request.respond(Message::builder().build().unwrap());
            }
        })
    }
}

struct PendingWriter;

impl AsyncWrite for PendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Poll::Pending
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn test_server_policy() -> TcpServerPolicy {
    TcpServerPolicy {
        connection_limit: 1,
        frame_read_timeout: Duration::from_secs(10),
        handler_reply_timeout: Duration::from_secs(10),
        max_axfr_validation_rrsets: MAX_AXFR_VALIDATION_RRSETS,
        response_write_timeout: Duration::from_secs(10),
    }
}

struct StatefulTcpHandler {
    peer: SocketAddr,
}

impl DnsRequestHandler for StatefulTcpHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            assert_eq!(request.peer(), self.peer);
            assert_eq!(request.protocol(), TransportProtocol::Tcp);
            let _ = request.respond(Message::builder().build().unwrap());
        })
    }
}

mod axfr_validation;
mod client_io;
mod framing_and_queries;
mod normalization_and_limits;
mod request_and_response;
mod server_limits;
mod support;

use support::{a_record, rrsig};

mod signed_axfr;

mod ixfr_stream;

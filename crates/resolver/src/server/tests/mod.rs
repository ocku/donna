use std::{
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use dns::{
    ClassType, DomainName, Headers, IntoWire, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use transport::TransportError;

use super::*;
use crate::ResolverConfig;

mod algorithm_signals;

mod edns;

#[derive(Clone, Copy)]
struct AnswerTransport;

#[derive(Clone)]
struct CountingTransport {
    calls: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct RecordingAnswerTransport {
    requests: Arc<Mutex<Vec<Message>>>,
}

impl Transport for AnswerTransport {
    fn exchange<'future>(
        &'future self,
        _server: std::net::SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let question = query.questions[0].clone();
            Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    ad: true,
                    ..Headers::default()
                },
                questions: vec![question.clone()],
                answers: vec![ResourceRecord {
                    name: question.qname,
                    rtype: RecordType::A,
                    class: ClassType::IN,
                    ttl: 60,
                    rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                }],
                authorities: Vec::new(),
                additionals: Vec::new(),
            })
        })
    }
}

impl Transport for CountingTransport {
    fn exchange<'future>(
        &'future self,
        _server: std::net::SocketAddr,
        _query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(TransportError::Timeout)
        })
    }
}

impl Transport for RecordingAnswerTransport {
    fn exchange<'future>(
        &'future self,
        _server: std::net::SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(query.clone());
            AnswerTransport
                .exchange((Ipv4Addr::LOCALHOST, 53).into(), query, Duration::ZERO)
                .await
        })
    }
}

fn request(recursion_desired: bool) -> Message {
    Message::builder()
        .headers(Headers {
            id: 42,
            rd: recursion_desired,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted("example.com").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

fn server() -> RecursiveServer<AnswerTransport> {
    RecursiveServer::with_resolver(Resolver::new(
        AnswerTransport,
        ResolverConfig {
            root_servers: vec![(Ipv4Addr::LOCALHOST, 53).into()],
            ..ResolverConfig::default()
        },
    ))
}

#[tokio::test]
async fn serves_recursive_answers_with_client_facing_headers() {
    let response = server().answer(&request(true)).await;

    assert_eq!(response.headers.id, 42);
    assert!(response.headers.qr);
    assert!(response.headers.rd);
    assert!(response.headers.ra);
    assert!(!response.headers.aa);
    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::A(address),
            ..
        }] if *address == Ipv4Addr::new(192, 0, 2, 1)
    ));
}

#[tokio::test]
async fn recursive_responses_copy_the_dnssec_ok_bit_without_claiming_ad() {
    let mut request = request(true);
    request.additionals.push(
        Edns {
            dnssec_ok: true,
            ..Edns::new(1232)
        }
        .into_record(),
    );

    let response = server().answer(&request).await;
    assert!(response.edns().unwrap().unwrap().dnssec_ok);
    assert!(!response.headers.ad);
}

#[test]
fn authenticated_data_requires_validation_client_support_and_no_cd() {
    let plain = request(true);
    assert!(!should_set_authenticated_data(
        &plain,
        true,
        &RequestEdns::new(&plain)
    ));

    let mut do_request = plain.clone();
    do_request.additionals.push(
        Edns {
            dnssec_ok: true,
            ..Edns::new(1232)
        }
        .into_record(),
    );
    assert!(should_set_authenticated_data(
        &do_request,
        true,
        &RequestEdns::new(&do_request)
    ));
    assert!(!should_set_authenticated_data(
        &do_request,
        false,
        &RequestEdns::new(&do_request)
    ));

    do_request.headers.cd = true;
    assert!(!should_set_authenticated_data(
        &do_request,
        true,
        &RequestEdns::new(&do_request)
    ));

    let mut ad_request = plain;
    ad_request.headers.ad = true;
    assert!(should_set_authenticated_data(
        &ad_request,
        true,
        &RequestEdns::new(&ad_request)
    ));
}

#[test]
fn dnssec_validation_failures_map_to_extended_errors() {
    assert_eq!(
        resolve_error_extended_code(&ResolveError::DnssecBogus(
            dns::DnssecValidationError::NoValidSignature,
        )),
        Some(ExtendedDnsErrorCode::DnssecBogus)
    );
    assert_eq!(
        resolve_error_extended_code(&ResolveError::DnssecIndeterminate(
            dns::DnssecValidationError::MissingTrustAnchor,
        )),
        Some(ExtendedDnsErrorCode::DnssecIndeterminate)
    );
}

#[test]
fn dnssec_proofs_are_hidden_without_do_unless_explicitly_queried() {
    let mut request = request(true);
    let owner = request.questions[0].qname.clone();
    let signature = ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::RRSIG(dns::Rrsig {
            type_covered: u16::from(RecordType::A),
            algorithm: 8,
            labels: 2,
            original_ttl: 60,
            signature_expiration: u32::MAX,
            signature_inception: 0,
            key_tag: 1,
            signer_name: DomainName::root(),
            signature: vec![1],
        }),
    };
    let mut response = Message {
        headers: Headers::default(),
        questions: request.questions.clone(),
        answers: vec![signature.clone()],
        authorities: vec![signature.clone()],
        additionals: vec![signature.clone()],
    };
    strip_unrequested_dnssec_records(&request, &mut response, &RequestEdns::new(&request));
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert!(response.additionals.is_empty());

    request.questions[0].qtype = QueryType::RRSIG;
    response.answers.push(signature);
    strip_unrequested_dnssec_records(&request, &mut response, &RequestEdns::new(&request));
    assert_eq!(response.answers.len(), 1);
}

#[tokio::test]
async fn recursive_queries_forward_algorithm_signals_but_responses_strip_them() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server = RecursiveServer::with_resolver(Resolver::new(
        RecordingAnswerTransport {
            requests: Arc::clone(&requests),
        },
        ResolverConfig {
            root_servers: vec![(Ipv4Addr::LOCALHOST, 53).into()],
            ..ResolverConfig::default()
        },
    ));
    let mut edns = Edns::new(1232);
    edns.set_algorithm_signal(dns::DnssecAlgorithmSignal::Dau, [8, 10])
        .unwrap();
    edns.set_algorithm_signal(dns::DnssecAlgorithmSignal::Dhu, [2])
        .unwrap();
    edns.set_algorithm_signal(dns::DnssecAlgorithmSignal::N3u, [1])
        .unwrap();
    let mut request = request(true);
    request.additionals.push(edns.into_record());

    let response = server.answer(&request).await;
    let outbound = requests.lock().unwrap();
    assert_eq!(outbound.len(), 1);
    let outbound_edns = outbound[0].edns().unwrap().unwrap();
    assert!(outbound_edns.dnssec_ok);
    assert_eq!(
        outbound_edns
            .algorithm_signal(dns::DnssecAlgorithmSignal::Dau)
            .unwrap(),
        Some([8, 10].as_slice())
    );
    assert_eq!(
        outbound_edns
            .algorithm_signal(dns::DnssecAlgorithmSignal::Dhu)
            .unwrap(),
        Some([2].as_slice())
    );
    assert_eq!(
        outbound_edns
            .algorithm_signal(dns::DnssecAlgorithmSignal::N3u)
            .unwrap(),
        Some([1].as_slice())
    );
    drop(outbound);

    let response_edns = response.edns().unwrap().unwrap();
    assert!(response_edns.dnssec_ok);
    for signal in [
        dns::DnssecAlgorithmSignal::Dau,
        dns::DnssecAlgorithmSignal::Dhu,
        dns::DnssecAlgorithmSignal::N3u,
    ] {
        assert_eq!(response_edns.algorithm_signal(signal).unwrap(), None);
    }
}

#[tokio::test]
async fn rejects_truncated_queries_without_resolving() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = RecursiveServer::with_resolver(Resolver::new(
        CountingTransport {
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec![(Ipv4Addr::LOCALHOST, 53).into()],
            max_steps: 1,
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    ));
    let mut request = request(true);
    request.headers.tc = true;

    let response = server.answer(&request).await;

    assert_eq!(response.headers.id, 42);
    assert!(response.headers.qr);
    assert_eq!(response.headers.opcode, OpCode::Query);
    assert!(response.headers.rd);
    assert!(response.headers.ra);
    assert!(!response.headers.tc);
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn refuses_queries_that_do_not_request_recursion() {
    let response = server().answer(&request(false)).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(response.headers.ra);
    assert!(response.answers.is_empty());
}

#[tokio::test]
async fn edns_refusal_without_recursion_includes_not_authoritative_ede() {
    let mut request = request(false);
    request.additionals.push(Edns::new(1232).into_record());

    let response = server().answer(&request).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    let edns = response.edns().unwrap().unwrap();
    // RFC 6891 erratum 8348: OPT CLASS describes the sender's receive
    // limit, so a recursive responder advertises its own value rather
    // than copying the requestor's 1232-octet value.
    assert_eq!(edns.udp_payload_size, Edns::RECOMMENDED_UDP_PAYLOAD_SIZE);
    let errors = edns
        .extended_dns_errors()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].info_code, ExtendedDnsErrorCode::NotAuthoritative);
}

#[tokio::test]
async fn recursive_requests_ignore_future_edns_z_flags() {
    let mut request = request(false);
    let mut opt = Edns::new(1232).into_record();
    opt.ttl |= 0x0123;
    request.additionals.push(opt);

    let response = server().answer(&request).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(response.edns().unwrap().is_some());
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn recursive_requests_accept_nonfinal_padding() {
    let mut request = request(false);
    request.additionals.push(
        Edns {
            options: vec![
                dns::EdnsOption::padding(3),
                dns::EdnsOption {
                    code: 65_000,
                    data: vec![1],
                },
            ],
            ..Edns::new(1232)
        }
        .into_record(),
    );

    let response = server().answer(&request).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(response.edns().unwrap().is_some());
}

#[tokio::test]
async fn recursive_requests_accept_non_nfc_ede_text() {
    let mut request = request(false);
    request.additionals.push(
        Edns {
            options: vec![dns::EdnsOption {
                code: dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
                data: [vec![0, 0], "Cafe\u{301}".as_bytes().to_vec()].concat(),
            }],
            ..Edns::new(1232)
        }
        .into_record(),
    );

    let response = server().answer(&request).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(response.edns().unwrap().is_some());
}

#[tokio::test]
async fn unsupported_edns_versions_return_badvers_without_resolving() {
    let mut request = request(true);
    request.additionals.push(
        Edns {
            version: 1,
            ..Edns::new(1232)
        }
        .into_record(),
    );

    let response = server().answer(&request).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert_eq!(response.extended_rcode(), 16);
    assert_eq!(response.edns().unwrap().unwrap().version, Edns::VERSION);
    assert!(response.answers.is_empty());
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn malformed_edns_forms_return_minimal_opt_bearing_formerr() {
    let opt = Edns::new(1232).into_record();

    let mut multiple = request(true);
    multiple.additionals = vec![opt.clone(), opt.clone()];

    let mut misplaced = request(true);
    misplaced.answers.push(opt.clone());

    let mut malformed_option = request(true);
    malformed_option.additionals.push(
        Edns {
            options: vec![dns::EdnsOption {
                code: dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
                data: vec![0],
            }],
            ..Edns::new(1232)
        }
        .into_record(),
    );

    for malformed in [multiple, misplaced, malformed_option] {
        let response = server().answer(&malformed).await;
        assert_eq!(response.headers.rcode, RCode::FormatError);
        assert_eq!(response.questions.len(), 1);
        assert!(response.answers.is_empty());
        assert!(response.authorities.is_empty());
        assert_eq!(response.additionals.len(), 1);
        assert!(response.edns().unwrap().is_some());
        assert!(response.into_wire().is_ok());
    }
}

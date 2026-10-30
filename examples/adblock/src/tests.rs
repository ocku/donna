use super::*;
use dns::{ClassType, Headers, QClassType, QueryType, Question, RData, RecordType, ResourceRecord};
use std::sync::atomic::{AtomicUsize, Ordering};

fn query(name: &str, qtype: QueryType) -> Message {
    Message::builder()
        .headers(Headers {
            id: 123,
            rd: true,
            ad: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted(name).unwrap(),
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

struct Upstream(Arc<AtomicUsize>);

impl Transport for Upstream {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        request: &'future Message,
        _timeout: Duration,
    ) -> BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);

            if server.port() == 9 {
                return Err(TransportError::Timeout);
            }

            let mut response = request.error_response(RCode::Ok, true);
            response.answers.push(ResourceRecord {
                name: request.questions[0].qname.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::A("192.0.2.42".parse().unwrap()),
            });

            Ok(response)
        })
    }
}

fn forwarder() -> (Forwarder<BlockingTransport<Upstream>>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));

    let forwarder = Forwarder::new(
        vec![(
            "127.0.0.1:53".parse().unwrap(),
            BlockingTransport {
                blocklist: Arc::new(
                    Blocklist::parse("# a comment\n Ads.Example. # inline\nads.example\n").unwrap(),
                ),
                upstream: Upstream(Arc::clone(&calls)),
            },
        )],
        ForwarderConfig::default(),
    );

    (forwarder, calls)
}

#[test]
fn upstreams_default_to_both_quad9_doq_addresses() {
    let upstreams = parse_upstreams(DEFAULT_UPSTREAM_ADDRS).unwrap();

    assert_eq!(
        upstreams,
        [
            "9.9.9.9:853".parse().unwrap(),
            "149.112.112.112:853".parse().unwrap()
        ]
    );

    let ipv6 = parse_upstreams(" [::1]:5353, 127.0.0.1:5353 ").unwrap();

    assert_eq!(ipv6.len(), 2);

    for invalid in ["", "1.1.1.1:53", "1.1.1.1:53,1.1.1.1:53", "1.1.1.1:53,"] {
        assert!(parse_upstreams(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[tokio::test]
async fn fails_over_to_second_upstream_without_sending_blocked_queries() {
    let blocklist = Arc::new(Blocklist::parse("ads.example").unwrap());
    let failed_calls = Arc::new(AtomicUsize::new(0));
    let healthy_calls = Arc::new(AtomicUsize::new(0));

    let peers = [
        ("127.0.0.1:9", Arc::clone(&failed_calls)),
        ("127.0.0.1:53", Arc::clone(&healthy_calls)),
    ]
    .into_iter()
    .map(|(address, calls)| {
        let transport = BlockingTransport {
            blocklist: Arc::clone(&blocklist),
            upstream: Upstream(calls),
        };

        (address.parse().unwrap(), transport)
    })
    .collect();

    let forwarder = Forwarder::new(
        peers,
        ForwarderConfig {
            max_attempts_per_server: 1,
            ..ForwarderConfig::default()
        },
    );

    let blocked = forwarder
        .answer_message(&query("ads.example", QueryType::A))
        .await;

    assert_eq!(blocked.headers.rcode, RCode::NameError);
    assert_eq!(failed_calls.load(Ordering::SeqCst), 0);
    assert_eq!(healthy_calls.load(Ordering::SeqCst), 0);

    let allowed = forwarder
        .answer_message(&query("www.example", QueryType::A))
        .await;

    assert_eq!(allowed.headers.rcode, RCode::Ok);
    assert_eq!(allowed.answers.len(), 1);
    assert_eq!(failed_calls.load(Ordering::SeqCst), 1);
    assert_eq!(healthy_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn parses_domains_and_matches_dns_label_boundaries() {
    let list = Blocklist::parse("# comment\n Ads.Example.\nads.example\n").unwrap();

    assert_eq!(list.0.len(), 1);

    for name in ["ads.example", "ADS.EXAMPLE.", "img.cdn.ads.example"] {
        assert!(list.contains(&DomainName::from_dotted(name).unwrap()));
    }

    for name in ["example", "notads.example", "ads.example.evil", "."] {
        assert!(!list.contains(&DomainName::from_dotted(name).unwrap()));
    }

    // A literal dot inside a wire label must not act as a name separator.
    let binary = DomainName::from_labels(vec![b"cdn.ads".to_vec(), b"example".to_vec()]).unwrap();

    assert!(!list.contains(&binary));
}

#[test]
fn rejects_empty_malformed_and_other_list_formats() {
    for input in [
        "",
        "# comment",
        ".",
        "ads..test",
        "local=/ads.test/",
        "0.0.0.0 ads.test",
        "||ads.test^",
        "*.ads.test",
        "https://ads.test",
        "ads.test\ninvalid/domain",
    ] {
        assert!(Blocklist::parse(input).is_err(), "accepted {input:?}");
    }

    assert!(Blocklist::parse(&format!("{}.test", "a".repeat(64))).is_err());
}

#[tokio::test]
async fn blocked_names_never_reach_upstream_for_any_record_type() {
    let (forwarder, calls) = forwarder();

    for name in ["ads.example", "cdn.ADS.EXAMPLE."] {
        for qtype in [
            QueryType::A,
            QueryType::AAAA,
            QueryType::TXT,
            QueryType::ANY,
        ] {
            for with_edns in [false, true] {
                let mut request = query(name, qtype);

                if with_edns {
                    request.additionals.push(Edns::default().into_record());
                }

                let response = forwarder.answer_message(&request).await;

                assert_eq!(response.headers.rcode, RCode::NameError);
                assert_eq!(response.headers.id, request.headers.id);
                assert!(response.headers.qr && response.headers.ra && response.headers.rd);
                assert!(!response.headers.ad && !response.headers.aa);
                assert!(response.answers.is_empty() && response.authorities.is_empty());

                let edns = response.edns().unwrap();
                assert_eq!(edns.is_some(), with_edns);

                if let Some(edns) = edns {
                    let errors = edns
                        .extended_dns_errors()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();

                    assert_eq!(errors[0].info_code, ExtendedDnsErrorCode::Blocked);
                }
            }
        }
    }

    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn allowed_answers_are_forwarded_and_cached_with_client_ids() {
    let (forwarder, calls) = forwarder();
    let mut request = query("notads.example", QueryType::A);

    let first = forwarder.answer_message(&request).await;

    assert_eq!(first.headers.rcode, RCode::Ok);
    assert_eq!(first.answers.len(), 1);

    request.headers.id += 1;
    let cached = forwarder.answer_message(&request).await;

    assert_eq!(cached.headers.id, request.headers.id);
    assert_eq!(cached.answers[0].rdata, first.answers[0].rdata);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn request_validation_precedes_blocking() {
    let (forwarder, calls) = forwarder();
    let mut request = query("ads.example", QueryType::A);

    request.headers.rd = false;

    assert_eq!(
        forwarder.answer_message(&request).await.headers.rcode,
        RCode::Refused
    );

    request.questions.clear();

    assert_eq!(
        forwarder.answer_message(&request).await.headers.rcode,
        RCode::FormatError
    );

    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

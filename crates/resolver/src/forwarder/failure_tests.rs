use super::*;
use dns::Headers;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
struct FailedPeer(Arc<AtomicUsize>);
impl Transport for FailedPeer {
    fn exchange<'a>(
        &'a self,
        _server: SocketAddr,
        _query: &'a Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, transport::TransportError>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(transport::TransportError::Timeout)
        })
    }
}
#[tokio::test]
async fn terminal_failures_are_suppressed_per_cd_mode_and_zero_disables_it() {
    for capacity in [0, 16] {
        let calls = Arc::new(AtomicUsize::new(0));
        let forwarder = Forwarder::new(
            vec![("127.0.0.1:53".parse().unwrap(), FailedPeer(calls.clone()))],
            ForwarderConfig {
                cache_capacity: capacity,
                max_attempts_per_server: 1,
                ..ForwarderConfig::default()
            },
        );
        let mut query = query();
        for _ in 0..2 {
            assert_eq!(
                forwarder.answer_message(&query).await.headers.rcode,
                RCode::ServerFailure
            );
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            if capacity == 0 { 2 } else { 1 }
        );
        query.headers.cd = true;
        forwarder.answer_message(&query).await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            if capacity == 0 { 3 } else { 2 }
        );
    }
}

fn query() -> Message {
    Message {
        headers: Headers {
            rd: true,
            ..Headers::default()
        },
        questions: vec![dns::Question {
            qname: dns::DomainName::from_dotted("example.test").unwrap(),
            qtype: dns::QueryType::A,
            qclass: dns::QClassType::Class(dns::ClassType::IN),
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
}

struct ReplyPeer {
    code: u16,
    calls: Arc<AtomicUsize>,
}

impl Transport for ReplyPeer {
    fn exchange<'a>(
        &'a self,
        _server: SocketAddr,
        query: &'a Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, transport::TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut response =
                query.error_response(RCode::try_from((self.code & 0x0f) as u8).unwrap(), true);
            response.additionals = vec![
                dns::Edns {
                    extended_rcode: (self.code >> 4) as u8,
                    ..dns::Edns::default()
                }
                .into_record(),
            ];
            // Even a peer's error reply containing cacheable-looking data
            // must not enter the success cache through its low RCODE bits.
            response.answers = vec![dns::ResourceRecord {
                name: query.questions[0].qname.clone(),
                rtype: RecordType::A,
                class: dns::ClassType::IN,
                ttl: 60,
                rdata: RData::A("192.0.2.1".parse().unwrap()),
            }];
            Ok(response)
        })
    }
}

#[tokio::test]
async fn extended_errors_do_not_alias_failure_codes_or_enter_the_cache() {
    for code in [16, 34, 37, 2, 5] {
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let forwarder = Forwarder::new(
            vec![
                (
                    "192.0.2.1:53".parse().unwrap(),
                    ReplyPeer {
                        code,
                        calls: first.clone(),
                    },
                ),
                (
                    "192.0.2.2:53".parse().unwrap(),
                    ReplyPeer {
                        code: 0,
                        calls: second.clone(),
                    },
                ),
            ],
            ForwarderConfig::default(),
        );
        let mut query = query();
        query.additionals.push(dns::Edns::default().into_record());
        let failover = matches!(code, 2 | 5);
        let answer = forwarder.answer_message(&query).await;
        assert_eq!(answer.extended_rcode(), if failover { 0 } else { code });
        assert_eq!(first.load(Ordering::Relaxed), 1);
        assert_eq!(second.load(Ordering::Relaxed), usize::from(failover));

        if failover {
            assert!(forwarder.try_answer_cached(&query).is_some());
        } else {
            assert!(forwarder.try_answer_cached(&query).is_none());
            assert_eq!(
                forwarder.answer_message(&query).await.extended_rcode(),
                code
            );
            assert_eq!(first.load(Ordering::Relaxed), 2);
            assert_eq!(second.load(Ordering::Relaxed), 0);
        }
    }
}

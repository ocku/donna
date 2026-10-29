use super::*;
use dns::{ClassType, DomainName, Edns, Headers, QClassType, QueryType, Question, ResourceRecord};

pub(super) struct UnusedTransport;
impl Transport for UnusedTransport {
    fn exchange<'a>(
        &'a self,
        _server: SocketAddr,
        _query: &'a Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, transport::TransportError>> {
        Box::pin(async { panic!("cache-policy tests must not exchange messages") })
    }
}

pub(super) fn fixture() -> (Forwarder<UnusedTransport>, Message, Message) {
    let f = Forwarder::new(Vec::new(), ForwarderConfig::default());
    let q = Message {
        headers: Headers {
            rd: true,
            ad: true,
            ..Headers::default()
        },
        questions: vec![Question {
            qname: DomainName::from_dotted("example.test").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };
    let mut r = q.error_response(RCode::Ok, true);
    r.answers.push(ResourceRecord {
        name: q.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A("192.0.2.1".parse().unwrap()),
    });
    (f, q, r)
}

#[test]
fn caches_age_and_recorrelate_without_crossing_cd_modes() {
    let (f, mut q, r) = fixture();
    f.remember(&q, &r);
    q.headers.id = 1234;
    let hit = f.cached(&q).unwrap();
    assert_eq!(hit.headers.id, 1234);
    assert!(hit.answers[0].ttl <= 60);
    q.headers.cd = true;
    assert!(f.cached(&q).is_none());
}

#[test]
fn expiration_zero_ttl_and_unproven_negatives_are_not_reused() {
    let (f, q, mut r) = fixture();
    r.answers[0].ttl = 0;
    f.remember(&q, &r);
    assert!(f.cached(&q).is_none());
    r.answers.clear();
    r.headers.rcode = RCode::NameError;
    f.remember(&q, &r);
    assert!(f.cached(&q).is_none());
    r.headers.rcode = RCode::Ok;
    r.answers = fixture().2.answers;
    f.remember(&q, &r);
    f.cache
        .lock()
        .unwrap()
        .values_mut()
        .for_each(|e| e.inserted = Instant::now() - Duration::from_secs(61));
    assert!(f.cached(&q).is_none());
}

#[test]
fn malformed_forwarding_queries_and_edns_version_are_rejected() {
    let (_, mut q, _) = fixture();
    q.additionals.push(
        Edns {
            version: 1,
            ..Edns::default()
        }
        .into_record(),
    );
    assert_eq!(validate(&q).unwrap().extended_rcode(), 16);
    q.questions.clear();
    assert_eq!(validate(&q).unwrap().headers.rcode, RCode::FormatError);
}

#[tokio::test]
async fn edns_errors_are_minimal_correlated_and_never_reach_an_upstream() {
    use dns::{EDNS_EXTENDED_DNS_ERROR_OPTION_CODE, EdnsOption, IntoWire};

    let forwarder = Forwarder::new(
        vec![("127.0.0.1:9".parse().unwrap(), UnusedTransport)],
        ForwarderConfig::default(),
    );
    for placement in ["valid", "duplicate", "misplaced", "named"] {
        for bits in 0..32 {
            let unsupported = bits & 1 != 0;
            let malformed_option = bits & 2 != 0;
            let extended_rcode = bits & 4 != 0;
            let dnssec_ok = bits & 8 != 0;
            let (_, mut query, _) = fixture();
            query.headers.id = 0x4d52;
            query.headers.rd = false;
            query.headers.cd = true;
            let mut opt = Edns {
                version: u8::from(unsupported),
                extended_rcode: u8::from(extended_rcode),
                dnssec_ok,
                z: if bits & 16 != 0 { 0x0123 } else { 0 },
                options: vec![EdnsOption {
                    code: if malformed_option {
                        EDNS_EXTENDED_DNS_ERROR_OPTION_CODE
                    } else {
                        65000
                    },
                    data: vec![7],
                }],
                ..Edns::new(1232)
            }
            .into_record();
            match placement {
                "duplicate" => query.additionals = vec![opt.clone(), opt],
                "misplaced" => query.answers.push(opt),
                "named" => {
                    opt.name = query.questions[0].qname.clone();
                    query.additionals.push(opt);
                }
                _ => query.additionals.push(opt),
            }
            let expected = if placement != "valid" || malformed_option {
                1
            } else if unsupported {
                16
            } else if extended_rcode {
                1
            } else {
                5
            };
            let immediate = forwarder.try_answer_cached(&query).unwrap();
            let asynchronous = forwarder.answer_message(&query).await;
            assert_eq!(immediate.extended_rcode(), expected, "{placement} {bits}");
            assert_eq!(immediate.headers.id, query.headers.id);
            assert!(immediate.headers.qr && immediate.headers.ra && immediate.headers.cd);
            assert!(!immediate.headers.rd);
            assert!(!immediate.headers.ad && !immediate.headers.aa && !immediate.headers.tc);
            assert_eq!(immediate.questions.len(), query.questions.len());
            for (actual, expected) in immediate.questions.iter().zip(&query.questions) {
                assert_eq!(actual.qname.as_ref(), expected.qname.as_ref());
                assert_eq!(actual.qtype, expected.qtype);
                assert_eq!(actual.qclass, expected.qclass);
            }
            assert!(immediate.answers.is_empty() && immediate.authorities.is_empty());
            assert_eq!(immediate.additionals.len(), 1);
            let edns = immediate.edns().unwrap().unwrap();
            assert_eq!(edns.version, Edns::VERSION);
            assert_eq!(edns.dnssec_ok, placement == "valid" && dnssec_ok);
            assert_eq!(edns.z, 0);
            assert!(edns.options.is_empty());
            assert_eq!(
                immediate.into_wire().unwrap(),
                asynchronous.into_wire().unwrap()
            );
        }
    }
}

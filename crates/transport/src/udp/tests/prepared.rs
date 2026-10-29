use super::*;
use crate::ImmediateUdpResponse;

struct PreparedHandler {
    prototype: Message,
    force_id: bool,
    force_large_budget: bool,
    calls: AtomicUsize,
}

struct BorrowedAuthority {
    prototype: Message,
    force_id: bool,
    calls: AtomicUsize,
}

impl DnsRequestHandler for BorrowedAuthority {
    fn try_handle_udp(
        &self,
        request: &Message,
        _: &[u8],
        _: SocketAddr,
        maximum: usize,
    ) -> Option<ImmediateUdpResponse> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut request = request.clone();
        if self.force_id {
            request.headers.id ^= 1;
        }
        let records: Vec<_> = self.prototype.authorities.iter().collect();
        Some(ImmediateUdpResponse::Encoded(
            dns::wire::EncodedReply::authoritative_negative(&request, &records, true, maximum)
                .unwrap()
                .unwrap(),
        ))
    }

    fn handle<'future>(&'future self, _: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            panic!("selected authoritative reply must not restart its handler");
        })
    }
}

impl DnsRequestHandler for PreparedHandler {
    fn try_handle_udp(
        &self,
        query: &Message,
        _: &[u8],
        _: SocketAddr,
        maximum: usize,
    ) -> Option<ImmediateUdpResponse> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut rendered_for = query.clone();
        if self.force_id {
            rendered_for.headers.id = rendered_for.headers.id.wrapping_add(1);
        }
        if self.force_large_budget {
            rendered_for.additionals[0] = Edns {
                dnssec_ok: true,
                ..Edns::new(1232)
            }
            .into_record();
        }
        let prepared = dns::wire::PreparedNegativeReply::from_message(&self.prototype)
            .unwrap()
            .unwrap();
        Some(ImmediateUdpResponse::Encoded(
            prepared
                .render(
                    &rendered_for,
                    &[20; 4],
                    if self.force_large_budget {
                        1232
                    } else {
                        maximum
                    },
                    true,
                )
                .unwrap(),
        ))
    }
    fn handle<'future>(&'future self, _: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            panic!("prepared reply must not restart the handler");
        })
    }
}
fn query() -> Message {
    Message::builder()
        .headers(Headers {
            id: 17,
            rd: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted("missing.example.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([Edns {
            dnssec_ok: true,
            ..Edns::new(1232)
        }
        .into_record()])
        .build()
        .unwrap()
}
fn prototype(large: bool) -> Message {
    let mut message = query();
    message.headers.qr = true;
    message.headers.ra = true;
    message.headers.ad = true;
    message.headers.rcode = RCode::NameError;
    let owner = DomainName::from_dotted("example.").unwrap();
    let record = |rtype, rdata| ResourceRecord {
        name: owner.clone(),
        rtype,
        class: ClassType::IN,
        ttl: 20,
        rdata,
    };
    let signature = |covered, size| {
        record(
            RecordType::RRSIG,
            RData::RRSIG(dns::Rrsig {
                type_covered: covered,
                algorithm: 15,
                labels: 1,
                original_ttl: 20,
                signature_expiration: 2,
                signature_inception: 1,
                key_tag: 1,
                signer_name: owner.clone(),
                signature: vec![covered as u8; size],
            }),
        )
    };
    message.authorities = vec![
        record(
            RecordType::SOA,
            RData::SOA {
                mname: DomainName::from_dotted("ns.example.").unwrap(),
                rname: owner.clone(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 20,
            },
        ),
        record(
            RecordType::NSEC,
            RData::NSEC(dns::Nsec {
                next_domain_name: DomainName::from_dotted("next.example.").unwrap(),
                type_bitmap: dns::TypeBitmap::new([6, 46, 47]).unwrap(),
            }),
        ),
        signature(6, if large { 650 } else { 64 }),
        signature(47, 64),
    ];
    message
}

#[tokio::test]
async fn checked_packets_match_the_normal_path_and_mismatches_are_discarded_once() {
    for force_id in [false, true] {
        let request = query();
        let prototype = prototype(false);
        let handler = PreparedHandler {
            prototype: prototype.clone(),
            force_id,
            force_large_budget: false,
            calls: AtomicUsize::new(0),
        };
        let ordinary = move |_: Message| {
            let response = prototype.clone();
            async move { response }
        };
        let wire = request.into_wire().unwrap();
        let expected = response_for(&ordinary, &wire).await.unwrap();
        let actual = response_for(&handler, &wire).await;
        if force_id {
            assert!(actual.is_none());
        } else {
            assert_eq!(actual.unwrap(), expected);
        }
        assert_eq!(handler.calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn actual_udp_limit_forces_the_existing_whole_rrset_truncation_path() {
    let mut request = query();
    request.additionals[0] = Edns {
        dnssec_ok: true,
        ..Edns::new(512)
    }
    .into_record();
    let prototype = prototype(true);
    assert!(prototype.into_wire().unwrap().len() > 512);
    let handler = PreparedHandler {
        prototype: prototype.clone(),
        force_id: false,
        force_large_budget: true,
        calls: AtomicUsize::new(0),
    };
    let ordinary = move |_: Message| {
        let response = prototype.clone();
        async move { response }
    };
    let wire = request.into_wire().unwrap();
    let expected = response_for(&ordinary, &wire).await.unwrap();
    let actual = response_for(&handler, &wire).await.unwrap();
    assert_eq!(actual, expected);
    assert!(actual.len() <= 512);
    assert!(Message::from_wire(&actual).unwrap().headers.tc);
    assert_eq!(handler.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn borrowed_authority_obeys_correlation_and_whole_rrset_limits_with_and_without_opt() {
    for edns in [false, true] {
        for large in [false, true] {
            for force_id in [false, true] {
                let mut request = query();
                request.additionals = if edns {
                    vec![
                        Edns {
                            dnssec_ok: true,
                            ..Edns::new(512)
                        }
                        .into_record(),
                    ]
                } else {
                    Vec::new()
                };
                let mut prototype = prototype(large);
                prototype.headers.aa = true;
                prototype.headers.ra = false;
                prototype.headers.ad = false;
                prototype.additionals = if edns {
                    vec![
                        Edns {
                            dnssec_ok: true,
                            ..Edns::default()
                        }
                        .into_record(),
                    ]
                } else {
                    Vec::new()
                };
                let handler = BorrowedAuthority {
                    prototype: prototype.clone(),
                    force_id,
                    calls: AtomicUsize::new(0),
                };
                let ordinary = move |_: Message| {
                    let response = prototype.clone();
                    async move { response }
                };
                let wire = request.into_wire().unwrap();
                let expected = response_for(&ordinary, &wire).await.unwrap();
                let actual = response_for(&handler, &wire).await;
                if force_id {
                    assert!(actual.is_none());
                } else {
                    let actual = actual.unwrap();
                    assert_eq!(actual, expected);
                    assert!(actual.len() <= 512);
                    assert_eq!(Message::from_wire(&actual).unwrap().headers.tc, large);
                }
                assert_eq!(handler.calls.load(Ordering::Relaxed), 1);
            }
        }
    }
}

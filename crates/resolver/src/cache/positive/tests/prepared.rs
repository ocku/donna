use super::*;
use dns::{Edns, FromWire};

fn fixture(last: u8) -> (Message, Message) {
    let mut request = question(7);
    request.additionals.push(
        Edns {
            dnssec_ok: true,
            ..Edns::new(1232)
        }
        .into_record(),
    );
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.headers.ad = true;
    reply.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, last)),
    });
    (request, reply)
}

#[test]
fn prepared_hits_fallback_expiry_and_replacement_use_one_selected_entry() {
    let cache = PositiveCache::new(1);
    let (request, reply) = fixture(1);
    assert!(cache.insert(&request, &reply, Duration::from_secs(60)));
    let Some(CachedPositiveUdp::Encoded(encoded)) = cache.get_udp(&request, 1232, true) else {
        panic!("expected prepared positive");
    };
    assert!(encoded.matches_request(&request));
    assert!(Message::from_wire(encoded.as_bytes()).unwrap().headers.ad);
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 1);
    assert!(matches!(
        cache.get_udp(&request, 20, true),
        Some(CachedPositiveUdp::Message(_))
    ));
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 2);
    let mut another_case = request.clone();
    another_case.questions[0].qname = DomainName::from_dotted("www.example.").unwrap();
    let Some(CachedPositiveUdp::Message(fallback)) = cache.get_udp(&another_case, 1232, true)
    else {
        panic!("case variation must retain ordinary handling");
    };
    assert_eq!(fallback.questions[0].qname, another_case.questions[0].qname);
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 3);
    {
        let mut entries = cache.entries.lock().unwrap();
        assert!(entries.values[0].prepared[1].get().unwrap().is_some());
        entries.modify(0, |entry| {
            entry.expires_at = Instant::now() + Duration::from_secs(2)
        });
    }
    let Some(CachedPositiveUdp::Encoded(encoded)) = cache.get_udp(&request, 1232, false) else {
        panic!("expected shortened prepared positive");
    };
    let shortened = Message::from_wire(encoded.as_bytes()).unwrap();
    assert!(shortened.answers[0].ttl <= 2);
    assert!(!shortened.headers.ad);
    {
        let mut entries = cache.entries.lock().unwrap();
        entries.modify(0, |entry| {
            entry.expires_at = Instant::now() - Duration::from_secs(1)
        });
    }
    assert!(cache.get_udp(&request, 1232, true).is_none());
    assert!(cache.entries.lock().unwrap().values.is_empty());
    let (_, replacement) = fixture(2);
    assert!(cache.insert(&request, &replacement, Duration::from_secs(60)));
    assert!(
        cache.entries.lock().unwrap().values[0].prepared[1]
            .get()
            .is_none()
    );
    let Some(CachedPositiveUdp::Encoded(encoded)) = cache.get_udp(&request, 1232, true) else {
        panic!("expected replacement prepared positive");
    };
    assert!(
        matches!(Message::from_wire(encoded.as_bytes()).unwrap().answers[0].rdata,
        RData::A(address) if address == Ipv4Addr::new(192, 0, 2, 2))
    );
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 1);
}

#[test]
fn selected_positive_retains_immutable_data_across_replacement_and_rejects_expired_lookup() {
    let cache = PositiveCache::new(1);
    let (request, reply) = fixture(1);
    assert!(cache.insert(&request, &reply, Duration::from_secs(60)));
    let selected = cache.select_question(&request.questions[0]).unwrap();
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 1);
    let (_, replacement) = fixture(2);
    assert!(cache.insert(&request, &replacement, Duration::from_secs(60)));
    assert!(matches!(selected.answers()[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192,0,2,1)));
    let current = cache.select_question(&request.questions[0]).unwrap();
    assert!(matches!(current.answers()[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192,0,2,2)));
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 1);
    {
        let mut entries = cache.entries.lock().unwrap();
        entries.modify(0, |entry| {
            entry.expires_at = Instant::now() - Duration::from_secs(1)
        });
    }
    assert!(cache.select_question(&request.questions[0]).is_none());
    assert!(cache.entries.lock().unwrap().values.is_empty());
}

#[test]
fn filtered_and_dnssec_variants_share_plain_edns_and_classic_without_extra_touches() {
    let cache = PositiveCache::new(1);
    let (mut request, reply) = fixture(1);
    assert!(cache.insert(&request, &reply, Duration::from_secs(60)));
    assert!(matches!(
        cache.get_udp(&request, 1232, true),
        Some(CachedPositiveUdp::Encoded(_))
    ));
    request.additionals.clear();
    assert!(matches!(
        cache.get_udp(&request, 4096, true),
        Some(CachedPositiveUdp::Encoded(_))
    ));
    let first = {
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.values[0].hits, 2);
        entries.values[0].prepared[0]
            .get()
            .unwrap()
            .as_ref()
            .unwrap()
            .as_ref() as *const _
    };
    request.additionals.push(Edns::new(1232).into_record());
    assert!(matches!(
        cache.get_udp(&request, 1232, true),
        Some(CachedPositiveUdp::Encoded(_))
    ));
    {
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.values[0].hits, 3);
        assert!(
            entries.values[0]
                .prepared
                .iter()
                .all(|slot| slot.get().unwrap().is_some())
        );
        assert_eq!(
            first,
            entries.values[0].prepared[0]
                .get()
                .unwrap()
                .as_ref()
                .unwrap()
                .as_ref() as *const _
        );
    }
    let (_, replacement) = fixture(2);
    assert!(cache.insert(&request, &replacement, Duration::from_secs(60)));
    assert!(
        cache.entries.lock().unwrap().values[0]
            .prepared
            .iter()
            .all(|slot| slot.get().is_none())
    );
}

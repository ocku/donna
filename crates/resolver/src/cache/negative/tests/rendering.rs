//! Prepared and selected negative response regression tests.

use super::*;

fn udp_request(question: Question, payload: u16) -> Message {
    Message::builder()
        .headers(Headers {
            rd: true,
            ..Headers::default()
        })
        .questions([question])
        .additionals([dns::Edns {
            dnssec_ok: true,
            ..dns::Edns::new(payload)
        }
        .into_record()])
        .build()
        .unwrap()
}

#[test]
fn prepared_cache_hits_touch_once_and_expiry_cannot_reuse_the_encoding() {
    let cache = NegativeCache::new(1);
    let q = question(QueryType::A);
    assert!(cache.insert(
        &q,
        &negative(RCode::NameError, 60, 30),
        true,
        Duration::from_secs(60)
    ));
    let request = udp_request(q.clone(), 1232);
    assert!(matches!(
        cache.get_udp(&request, 1232, false),
        Some(CachedNegativeUdp::Encoded { .. })
    ));
    {
        let mut entries = cache.entries.lock().unwrap();
        assert_eq!(entries.values[0].hits, 1);
        assert!(entries.values[0].prepared[1].get().unwrap().is_some());
        entries.modify(0, |entry| {
            entry.expires_at = Instant::now() - Duration::from_secs(1)
        });
    }
    assert!(cache.get_udp(&request, 1232, false).is_none());
    assert!(cache.entries.lock().unwrap().values.is_empty());
}

#[test]
fn prepared_fallback_keeps_one_touch_and_filters_expired_optional_ns() {
    let cache = NegativeCache::new(1);
    let q = question(QueryType::A);
    let mut response = negative(RCode::NameError, 60, 30);
    response.authorities.push(ResourceRecord {
        name: name(&["example"]),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 1,
        rdata: RData::NS(name(&["ns", "example"])),
    });
    assert!(cache.insert(&q, &response, true, Duration::from_secs(60)));
    let request = udp_request(q, 1232);
    assert!(matches!(
        cache.get_udp(&request, 1232, false),
        Some(CachedNegativeUdp::Encoded { .. })
    ));
    {
        let mut entries = cache.entries.lock().unwrap();
        Arc::get_mut(&mut entries.values[0].authorities)
            .unwrap()
            .records
            .iter_mut()
            .find(|cached| cached.record.rtype == RecordType::NS)
            .unwrap()
            .expires_at = Instant::now() - Duration::from_secs(1);
    }
    let Some(CachedNegativeUdp::Message(response)) = cache.get_udp(&request, 1232, false) else {
        panic!("expected ordinary projection");
    };
    assert!(
        response
            .authorities
            .iter()
            .all(|record| record.rtype != RecordType::NS)
    );
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 2);
}

#[test]
fn plain_negative_variants_keep_deadline_mapping_and_explicit_query_isolation() {
    use dns::{Edns, FromWire};
    let cache = NegativeCache::new(1);
    let q = question(QueryType::A);
    let mut response = negative(RCode::NameError, 60, 30);
    response.authorities.extend([
        nsec_record(name(&["example"]), name(&["z", "example"]), 30),
        ResourceRecord {
            name: name(&["example"]),
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 17,
            rdata: RData::NS(name(&["ns", "example"])),
        },
    ]);
    assert!(cache.insert(&q, &response, true, Duration::from_secs(60)));
    // An explicit query first must leave the shared ordinary variant untouched.
    let mut request = udp_request(question(QueryType::NSEC), 1232);
    request.additionals = vec![Edns::new(1232).into_record()];
    assert!(matches!(
        cache.get_udp(&request, 1232, false),
        Some(CachedNegativeUdp::Message(_))
    ));
    assert!(
        cache.entries.lock().unwrap().values[0].prepared[0]
            .get()
            .is_none()
    );
    for classic in [false, true] {
        request.questions[0] = q.clone();
        request.additionals = if classic {
            vec![]
        } else {
            vec![Edns::new(1232).into_record()]
        };
        let Some(CachedNegativeUdp::Encoded {
            reply,
            implicit_referral,
        }) = cache.get_udp(&request, 4096, false)
        else {
            panic!("plain negative should use checked encoding")
        };
        assert!(!implicit_referral);
        let decoded = Message::from_wire(reply.as_bytes()).unwrap();
        assert_eq!(decoded.authorities.len(), 2);
        assert_eq!(decoded.authorities[0].rtype, RecordType::SOA);
        assert_eq!(decoded.authorities[1].rtype, RecordType::NS);
        assert!(decoded.authorities[1].ttl <= 17);
        assert!(decoded.authorities[0].ttl > decoded.authorities[1].ttl);
        assert_eq!(decoded.additionals.is_empty(), classic);
    }
    request = udp_request(q.clone(), 1232);
    assert!(matches!(
        cache.get_udp(&request, 1232, false),
        Some(CachedNegativeUdp::Encoded { .. })
    ));
    {
        let entries = cache.entries.lock().unwrap();
        let entry = &entries.values[0];
        assert_eq!(entry.hits, 4);
        assert_eq!(
            &*entry.prepared[0].get().unwrap().as_ref().unwrap().indices,
            &[0, 2]
        );
        assert_eq!(
            &*entry.prepared[1].get().unwrap().as_ref().unwrap().indices,
            &[0, 1, 2]
        );
    }
    request.questions[0].qtype = QueryType::NSEC;
    request.additionals.clear();
    assert!(matches!(
        cache.get_udp(&request, 512, false),
        Some(CachedNegativeUdp::Message(_))
    ));
    // Replacement drops both variants along with their original deadlines.
    assert!(cache.insert(
        &q,
        &negative(RCode::NameError, 60, 30),
        true,
        Duration::from_secs(60)
    ));
    assert!(
        cache.entries.lock().unwrap().values[0]
            .prepared
            .iter()
            .all(|slot| slot.get().is_none())
    );
}

#[test]
fn selected_negative_keeps_one_touched_entry_across_replacement_and_expiry() {
    let cache = NegativeCache::new(4);
    let q = question(QueryType::A);
    let mut reply = negative(RCode::NameError, 60, 30);
    reply.headers.ad = true;
    reply.authorities.push(ResourceRecord {
        name: name(&["example"]),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(name(&["old", "example"])),
    });
    assert!(cache.insert(&q, &reply, true, Duration::from_secs(60)));
    assert!(
        cache.entries.lock().unwrap().values[0]
            .authorities
            .iter()
            .all(|record| record.record.rtype != RecordType::NS)
    );
    let mut selected = cache.select(&q).unwrap();
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 1);
    assert_eq!(selected.authorities().count(), 1);
    assert!(selected.authenticated);
    assert_eq!(selected.rcode, RCode::NameError);
    // Replacement cannot change this query's already-selected storage or trust.
    assert!(cache.insert(
        &q,
        &negative(RCode::Ok, 60, 30),
        true,
        Duration::from_secs(60)
    ));
    let materialized = selected.materialize(&q);
    assert_eq!(materialized.headers.rcode, RCode::NameError);
    assert!(materialized.headers.ad);
    assert_eq!(materialized.authorities.len(), 1);
    assert_eq!(cache.entries.lock().unwrap().values[0].hits, 0);
    // A live-at-selection record may finish at zero, but never disappear or
    // regain a positive TTL after its absolute deadline.
    selected.expires_at = selected.selected_at + Duration::from_nanos(1);
    let materialized = selected.materialize(&q);
    assert_eq!(materialized.authorities.len(), 1);
    assert_eq!(materialized.authorities[0].ttl, 0);
}

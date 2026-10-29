use super::*;

#[test]
fn checked_ns_append_preserves_sections_offsets_spelling_and_limits() {
    let original = reply();
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    let mut encoded = prepared.render(&query(), &[20; 4], 1232, true).unwrap();
    let mut nameserver = ns();
    nameserver.ttl = 17;
    assert!(encoded.append_name_servers(std::slice::from_ref(&nameserver)));
    let actual = encoded.into_message().unwrap();
    let mut expected = original.clone();
    for record in &mut expected.authorities {
        record.ttl = 20;
    }
    expected.authorities.push(nameserver);
    assert_eq!(actual.into_wire().unwrap(), expected.into_wire().unwrap());
    assert!(actual.edns().unwrap().unwrap().dnssec_ok);
    let mut encoded = prepared
        .render(
            &query(),
            &[20; 4],
            original.into_wire().unwrap().len(),
            true,
        )
        .unwrap();
    let unchanged = encoded.as_bytes().to_vec();
    assert!(!encoded.append_name_servers(&[ns()]));
    assert_eq!(encoded.as_bytes(), unchanged);
}

#[test]
fn invalid_ns_sets_are_rejected_atomically_and_correlation_is_checked() {
    let prepared = PreparedNegativeReply::from_message(&reply())
        .unwrap()
        .unwrap();
    let base = ns();
    let mut other = base.clone();
    other.ttl = 1;
    let mut wrong_class = base.clone();
    wrong_class.class = ClassType::CH;
    let mut outside = base.clone();
    outside.name = name("elsewhere.test.");
    for set in [
        vec![base.clone(), base.clone()],
        vec![base.clone(), other],
        vec![wrong_class],
        vec![outside],
    ] {
        let mut encoded = prepared.render(&query(), &[20; 4], 1232, true).unwrap();
        let unchanged = encoded.as_bytes().to_vec();
        assert!(!encoded.append_name_servers(&set));
        assert_eq!(encoded.as_bytes(), unchanged);
    }
    let encoded = prepared.render(&query(), &[20; 4], 1232, true).unwrap();
    let mut changed = query();
    changed.headers.id += 1;
    assert!(!encoded.matches_request(&changed));
    let mut changed = query();
    changed.questions[0].qname = name("MISSING.example.test.");
    assert!(!encoded.matches_request(&changed));
}

#[test]
fn classic_negative_ns_overflow_leaves_checked_packet_unchanged() {
    let mut original = reply();
    original.authorities.truncate(1);
    original.additionals = vec![Edns::default().into_record()];
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    let mut request = query();
    request.additionals.clear();
    let mut encoded = prepared.render(&request, &[20], 4096, false).unwrap();
    let before = encoded.as_bytes().to_vec();
    let records: Vec<_> = (0..20)
        .map(|i| {
            let mut record = ns();
            record.rdata = RData::NS(name(&format!("nameserver-{i}.example.test.")));
            record
        })
        .collect();
    assert!(!encoded.append_name_servers(&records));
    assert_eq!(encoded.as_bytes(), before);
    assert!(encoded.append_name_servers(&[ns()]));
    assert!(encoded.as_bytes().len() <= 512);
}

#[test]
fn implicit_ns_append_declines_positive_ns_answers_without_mutation() {
    let mut request = query();
    request.questions[0].qname = name("example.test.");
    request.questions[0].qtype = QueryType::NS;
    for classic in [false, true] {
        if classic {
            request.additionals.clear();
        }
        let nameserver = ns();
        let mut response = request.clone();
        response.headers.qr = true;
        response.headers.ra = true;
        response.answers = vec![nameserver.clone()];
        response.additionals = vec![
            Edns {
                dnssec_ok: !classic,
                ..Edns::default()
            }
            .into_record(),
        ];
        let prepared = PreparedPositiveReply::from_message(&response)
            .unwrap()
            .unwrap();
        let mut rendered = prepared.render(&request, 20, 1232, false).unwrap();
        let before = rendered.as_bytes().to_vec();
        assert!(!rendered.append_name_servers(std::slice::from_ref(&nameserver)));
        assert_eq!(rendered.as_bytes(), before);
        let mut borrowed =
            EncodedReply::recursive_positive(&request, &[(&nameserver, 20)], &[], false, 1232)
                .unwrap()
                .unwrap();
        let before = borrowed.as_bytes().to_vec();
        assert!(!borrowed.append_name_servers(std::slice::from_ref(&nameserver)));
        assert_eq!(borrowed.as_bytes(), before);
    }
}

#[test]
fn ns_append_preserves_binary_and_long_literal_names_and_final_opt() {
    let mut original = reply();
    original.authorities.truncate(1);
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    let long = DomainName::from_labels(vec![vec![b'x']; 120]).unwrap();
    let binary = DomainName::from_labels(vec![
        vec![0, 255, b'A'],
        b"EXAMPLE".to_vec(),
        b"test".to_vec(),
    ])
    .unwrap();
    let records: Vec<_> = [DomainName::root(), long, binary]
        .into_iter()
        .map(|target| {
            let mut record = ns();
            record.rdata = RData::NS(target);
            record
        })
        .collect();
    let mut encoded = prepared.render(&query(), &[20], 1232, true).unwrap();
    assert!(encoded.append_name_servers(&records));
    let actual = encoded.into_message().unwrap();
    let mut expected = original;
    expected.authorities[0].ttl = 20;
    expected.authorities.extend(records);
    assert_eq!(actual.into_wire().unwrap(), expected.into_wire().unwrap());
}

use super::*;

#[test]
fn rejects_questions_the_iterative_api_cannot_complete() {
    let mut query = question(&["example"]);
    query.qtype = QueryType::AXFR;
    assert!(matches!(
        validate_question(&query),
        Err(ResolveError::UnsupportedQuestion)
    ));

    query.qtype = QueryType::IXFR;
    assert!(matches!(
        validate_question(&query),
        Err(ResolveError::UnsupportedQuestion)
    ));

    query.qtype = QueryType::A;
    query.qclass = QClassType::ANY;
    assert!(matches!(
        validate_question(&query),
        Err(ResolveError::UnsupportedQuestion)
    ));

    // RFC 1035 §3.2.5 defines only CLASS 255 beyond the CLASS values; an
    // unassigned class cannot be delegated through the IN-oriented SLIST.
    query.qclass = QClassType::Unknown(3);
    assert!(matches!(
        validate_question(&query),
        Err(ResolveError::UnsupportedQuestion)
    ));

    query.qclass = QClassType::Class(ClassType::Unknown(42));
    assert!(matches!(
        validate_question(&query),
        Err(ResolveError::UnsupportedQuestion)
    ));

    query.qclass = QClassType::Class(ClassType::IN);
    for qtype in [
        QueryType::Unknown(0),
        QueryType::Unknown(1),
        QueryType::Unknown(28),
        QueryType::Unknown(251),
        QueryType::Unknown(257),
        QueryType::Unknown(u16::MAX),
    ] {
        query.qtype = qtype;
        assert!(matches!(
            validate_question(&query),
            Err(ResolveError::UnsupportedQuestion)
        ));
    }

    query.qtype = QueryType::CAA;
    assert!(validate_question(&query).is_ok());
}

#[test]
fn classifies_answers_nodata_and_nxdomain_as_terminal() {
    let query = question(&["www", "example"]);
    let headers = |rcode: RCode, aa: bool| Headers {
        qr: true,
        aa,
        rcode,
        ..Headers::default()
    };

    // A matching answer ends resolution regardless of the AA bit.
    let answered = Message {
        headers: headers(RCode::Ok, false),
        questions: vec![query.clone()],
        answers: vec![a_record(query.qname.clone(), 1)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    assert!(is_terminal_response(&answered, &query));

    // Negative assertions are terminal only when made by an authoritative
    // server. A matching positive answer remains usable without AA.
    let mut nodata = answered.clone();
    nodata.answers.clear();
    assert!(!is_terminal_response(&nodata, &query));
    nodata.headers.aa = true;
    assert!(is_terminal_response(&nodata, &query));

    let mut name_error = nodata.clone();
    name_error.headers.aa = false;
    name_error.headers.rcode = RCode::NameError;
    assert!(!is_terminal_response(&name_error, &query));
    name_error.headers.aa = true;
    assert!(is_terminal_response(&name_error, &query));

    // Server-side failures must not end resolution: the resolver keeps
    // trying the other servers in the current SLIST.
    for rcode in [
        RCode::FormatError,
        RCode::ServerFailure,
        RCode::NotImplemented,
        RCode::Refused,
        RCode::Unknown(11),
    ] {
        let mut reply = nodata.clone();
        reply.headers.rcode = rcode;
        assert!(!is_terminal_response(&reply, &query), "rcode {rcode:?}");
    }
    assert!(is_terminal_response(&name_error, &query));

    // Ordinary positive data contradicts NXDOMAIN and must be treated as a
    // bizarre response so another server can be tried. CNAMEs are allowed.
    name_error.answers = vec![a_record(query.qname.clone(), 2)];
    assert!(!is_terminal_response(&name_error, &query));
    name_error.answers = vec![cname_record(
        query.qname.clone(),
        name(&["missing", "example"]),
    )];
    assert!(is_terminal_response(&name_error, &query));

    // RFC 2308 §2.2 allows legacy SIG and RRSIG metadata in a NODATA
    // answer. An applicable SOA makes it terminal, while ordinary answer
    // data makes the response unusable.
    let mut signed_nodata = nodata;
    signed_nodata.answers = vec![
        record(
            query.qname.clone(),
            RecordType::SIG,
            RData::SIG(dns::Sig {
                type_covered: 1,
                algorithm: 1,
                labels: 2,
                original_ttl: 60,
                signature_expiration: 2,
                signature_inception: 1,
                key_tag: 1,
                signer_name: DomainName::root(),
                signature: vec![1],
            }),
        ),
        rrsig_record(query.qname.clone(), RecordType::A, 2),
    ];
    signed_nodata.authorities = vec![soa_record(name(&["example"]))];
    assert!(is_terminal_response(&signed_nodata, &query));
    signed_nodata
        .answers
        .push(a_record(name(&["other", "example"]), 2));
    assert!(!is_terminal_response(&signed_nodata, &query));
}

#[test]
fn selects_only_safe_positive_data_for_cache_entries() {
    let query = question(&["www", "example"]);
    let answer = a_record(query.qname.clone(), 1);
    let clean = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![answer.clone()],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    assert_eq!(positive_cache_entries(&clean, &query).len(), 1);

    // A contradictory NXDOMAIN and an empty answer are not positive cache
    // material.
    let mut reply = clean.clone();
    reply.headers.rcode = RCode::NameError;
    assert!(positive_cache_entries(&reply, &query).is_empty());

    // The alias itself remains positive data when its canonical target is
    // NXDOMAIN. Its standalone cache entry must not retain the negative
    // RCODE or create a CNAME-only entry under the original A key.
    let target = name(&["missing", "example"]);
    reply.answers = vec![cname_record(query.qname.clone(), target)];
    let entries = positive_cache_entries(&reply, &query);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0.qtype, QueryType::CNAME);
    assert_eq!(entries[0].1.headers.rcode, RCode::Ok);
    assert_eq!(entries[0].1.answers.len(), 1);

    let mut reply = clean.clone();
    reply.answers.clear();
    assert!(positive_cache_entries(&reply, &query).is_empty());

    // Data for another owner, type, or class must not become the cached
    // answer for this question (RFC 1035 §7.4).
    let mut reply = clean.clone();
    reply.answers[0] = a_record(name(&["other", "example"]), 2);
    assert!(positive_cache_entries(&reply, &query).is_empty());
    let mut reply = clean.clone();
    reply.answers[0].rtype = RecordType::TXT;
    reply.answers[0].rdata = RData::TXT(vec![b"v=spf1".to_vec()]);
    assert!(positive_cache_entries(&reply, &query).is_empty());
    let mut reply = clean.clone();
    reply.answers[0].class = ClassType::CH;
    assert!(positive_cache_entries(&reply, &query).is_empty());

    // Unrelated answer, authority, and additional records do not prevent
    // caching the requested RRset, but none may be promoted into the entry.
    let mut reply = clean.clone();
    reply.answers.push(a_record(name(&["other", "example"]), 2));
    reply.authorities = vec![record(
        name(&["example"]),
        RecordType::NS,
        RData::NS(name(&["ns", "example"])),
    )];
    reply.additionals = vec![a_record(name(&["ns", "example"]), 3)];
    let entries = positive_cache_entries(&reply, &query);
    let (_, selected) = entries.last().unwrap();
    assert_eq!(selected.answers.len(), 1);
    assert!(selected.answers[0].name.eq_dns(&answer.name));
    assert_eq!(selected.answers[0].rtype, answer.rtype);
    assert_eq!(selected.answers[0].rdata, answer.rdata);
    assert!(selected.authorities.is_empty());
    assert!(selected.additionals.is_empty());

    // QCLASS * cannot be attributed to a single cached class.
    let mut any_query = query.clone();
    any_query.qclass = QClassType::ANY;
    assert!(positive_cache_entries(&clean, &any_query).is_empty());
}

#[test]
fn caches_aggregate_keys_only_from_authoritative_answers() {
    let mut query = question(&["www", "example"]);
    query.qtype = QueryType::ANY;
    let mut reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![a_record(query.qname.clone(), 1)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    let entries = positive_cache_entries(&reply, &query);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0.qtype, QueryType::A);

    reply.headers.aa = true;
    let entries = positive_cache_entries(&reply, &query);
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|(question, _)| question.qtype == QueryType::ANY)
    );
}

#[test]
fn ranks_only_directly_authoritative_cache_entries_as_authoritative() {
    let query = question(&["www", "example"]);
    let first = name(&["first", "example"]);
    let canonical = name(&["canonical", "example"]);
    let reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![
            cname_record(query.qname.clone(), first.clone()),
            cname_record(first.clone(), canonical.clone()),
            a_record(canonical.clone(), 1),
        ],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    let entries = positive_cache_entries(&reply, &query);
    let entry = |owner: &DomainName, qtype| {
        entries
            .iter()
            .find(|(question, _)| question.qname.eq_dns(owner) && question.qtype == qtype)
            .map(|(_, reply)| reply)
            .unwrap()
    };

    assert!(entry(&query.qname, QueryType::CNAME).headers.aa);
    assert!(!entry(&query.qname, QueryType::A).headers.aa);
    assert!(!entry(&first, QueryType::CNAME).headers.aa);
    assert!(!entry(&canonical, QueryType::A).headers.aa);

    let direct = Message {
        answers: vec![a_record(query.qname.clone(), 2)],
        ..reply
    };
    assert!(
        positive_cache_entries(&direct, &query)
            .iter()
            .all(|(_, entry)| entry.headers.aa)
    );
}

#[test]
fn authoritative_any_selection_caches_each_rrsig_once() {
    use std::time::Duration;

    let mut query = question(&["www", "example"]);
    query.qtype = QueryType::ANY;
    let request = Message {
        questions: vec![query.clone()],
        ..Message::builder().build_unchecked()
    };
    let reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..request.headers.clone()
        },
        questions: vec![query.clone()],
        answers: vec![
            a_record(query.qname.clone(), 1),
            rrsig_record(query.qname.clone(), RecordType::A, 7),
        ],
        ..Message::builder().build_unchecked()
    };
    let cache = crate::cache::positive::PositiveCache::new(10);
    let entries = positive_cache_entries(&reply, &query);
    let (_, selected) = entries
        .iter()
        .find(|(question, _)| question.qtype == QueryType::ANY)
        .expect("aggregate cache entry");
    assert_eq!(selected.answers.len(), 2);
    assert_eq!(selected.answers[0].rdata, reply.answers[0].rdata);
    assert_eq!(selected.answers[1].rdata, reply.answers[1].rdata);
    for (question, response) in entries {
        let request = Message {
            questions: vec![question],
            ..request.clone()
        };
        assert!(cache.insert(&request, &response, Duration::from_secs(60)));
    }
    let cached = cache.get(&request).expect("ANY admitted to cache");
    assert_eq!(cached.answers.len(), 2);
    for (actual, expected) in cached.answers.iter().zip(&reply.answers) {
        assert_eq!(actual.rtype, expected.rtype);
        assert_eq!(actual.rdata, expected.rdata);
    }
}

#[test]
fn dname_derived_cname_is_not_cached_independently_of_its_proof() {
    let query = question(&["www", "old", "example"]);
    let dname = ResourceRecord {
        name: name(&["old", "example"]),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 10,
        rdata: RData::DNAME(name(&["new", "other"])),
    };
    let target = name(&["www", "new", "other"]);
    let mut reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![
            dname.clone(),
            cname_record(query.qname.clone(), target.clone()),
            a_record(target, 1),
        ],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    for rcode in [RCode::Ok, RCode::NameError] {
        reply.headers.rcode = rcode;
        assert!(positive_cache_entries(&reply, &query).is_empty());
    }
    let owner_question = Question {
        qname: dname.name.clone(),
        qtype: QueryType::DNAME,
        qclass: query.qclass,
    };
    reply.questions = vec![owner_question.clone()];
    reply.headers.rcode = RCode::Ok;
    reply.answers = vec![dname];
    assert_eq!(positive_cache_entries(&reply, &owner_question).len(), 1);
}

#[test]
fn dname_negative_requires_a_connected_exact_synthesis() {
    let query = question(&["www", "old", "example"]);
    let dname = ResourceRecord {
        name: name(&["old", "example"]),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::DNAME(name(&["new", "other"])),
    };
    let cname = cname_record(query.qname.clone(), name(&["www", "new", "other"]));
    let mut reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![dname, cname],
        authorities: vec![],
        additionals: vec![],
    };
    assert!(super::super::has_dname_negative_answer_metadata(
        &reply.answers,
        &query
    ));
    assert!(is_terminal_response(&reply, &query));
    let mut signed = reply.clone();
    signed.answers.push(rrsig_record(
        name(&["old", "example"]),
        RecordType::DNAME,
        1,
    ));
    assert!(super::super::has_dname_negative_answer_metadata(
        &signed.answers,
        &query
    ));
    signed.answers.push(rrsig_record(
        name(&["unrelated", "example"]),
        RecordType::DNAME,
        1,
    ));
    assert!(!super::super::has_dname_negative_answer_metadata(
        &signed.answers,
        &query
    ));
    let mut synthetic_signature = reply.clone();
    synthetic_signature
        .answers
        .push(rrsig_record(query.qname.clone(), RecordType::CNAME, 1));
    assert!(!super::super::has_dname_negative_answer_metadata(
        &synthetic_signature.answers,
        &query
    ));
    reply.answers[1].rdata = RData::CNAME(name(&["forged", "other"]));
    assert!(!super::super::has_dname_negative_answer_metadata(
        &reply.answers,
        &query
    ));
    assert!(!is_terminal_response(&reply, &query));
    reply.answers[1].rdata = RData::CNAME(name(&["www", "new", "other"]));
    reply
        .answers
        .push(a_record(name(&["unrelated", "other"]), 9));
    assert!(!super::super::has_dname_negative_answer_metadata(
        &reply.answers,
        &query
    ));
    assert!(!is_terminal_response(&reply, &query));
}

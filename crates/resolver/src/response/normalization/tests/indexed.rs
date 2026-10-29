use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord, Rrsig,
};

use super::normalize_response_rrsets;

fn question() -> Question {
    Question {
        qname: DomainName::from_dotted("www.example.").unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn address(name: &str, ttl: u32, value: u32) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_dotted(name).unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl,
        rdata: RData::A(std::net::Ipv4Addr::from(0xc0000200 + value)),
    }
}

fn fillers(prefix: &str) -> Vec<ResourceRecord> {
    (0..40)
        .map(|index| address(&format!("{prefix}{index}.example."), 60, index))
        .collect()
}

fn response() -> Message {
    Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![question()],
        answers: fillers("answer"),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn signature(covered: RecordType, value: u8, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: question().qname,
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl,
        rdata: RData::RRSIG(Rrsig {
            type_covered: covered.into(),
            algorithm: 15,
            labels: 2,
            original_ttl: 60,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: DomainName::from_dotted("example.").unwrap(),
            signature: vec![value],
        }),
    }
}

#[test]
fn large_answers_normalize_only_authoritative_owner_and_preserve_first_duplicate() {
    let mut reply = response();
    let first = address("WWW.Example.", 90, 1);
    reply.answers.insert(7, first.clone());
    reply.answers.extend([
        address("www.EXAMPLE.", 30, 2),
        address("www.example.", 60, 1),
        address("other.example.", 90, 3),
        address("OTHER.example.", 10, 4),
    ]);
    assert!(normalize_response_rrsets(&mut reply, &question()));
    let selected: Vec<_> = reply
        .answers
        .iter()
        .filter(|record| record.name == question().qname)
        .collect();
    assert_eq!(selected.len(), 2);
    assert!(selected.iter().all(|record| record.ttl == 30));
    assert_eq!(selected[0].name.as_ref(), first.name.as_ref());
    assert_eq!(selected[0].rdata, first.rdata);
    assert_eq!(reply.answers[7].rdata, first.rdata);
    assert!(
        !reply
            .answers
            .iter()
            .any(|record| record.name == DomainName::from_dotted("other.example.").unwrap())
    );
}

#[test]
fn large_untrusted_mixed_ttl_rrset_is_removed_whole_and_requires_retry() {
    let mut reply = response();
    reply.headers.aa = false;
    reply.answers.extend([
        address("www.example.", 60, 1),
        address("WWW.example.", 30, 2),
        address("www.example.", 60, 3),
    ]);
    assert!(!normalize_response_rrsets(&mut reply, &question()));
    assert_eq!(reply.answers.len(), 40);
    assert!(
        !reply
            .answers
            .iter()
            .any(|record| record.name == question().qname)
    );
}

#[test]
fn large_sections_keep_class_type_and_label_boundaries_separate() {
    let mut reply = response();
    let mut literal_label = address("www.example.", 17, 1);
    literal_label.name = DomainName::from_labels(vec![b"www.example".to_vec()]).unwrap();
    let mut other_class = address("www.example.", 23, 1);
    other_class.class = ClassType::CH;
    other_class.rdata = RData::Unknown(vec![1, 2, 3, 4]);
    let mut other_type = address("www.example.", 41, 1);
    other_type.rtype = RecordType::AAAA;
    other_type.rdata = RData::AAAA("2001:db8::1".parse().unwrap());
    reply.answers.extend([
        literal_label,
        other_class,
        other_type,
        address("WWW.example.", 90, 1),
        address("www.example.", 30, 2),
    ]);
    assert!(normalize_response_rrsets(&mut reply, &question()));
    let ttls: Vec<_> = reply
        .answers
        .iter()
        .skip(40)
        .map(|record| record.ttl)
        .collect();
    assert_eq!(ttls, [17, 23, 41, 30, 30]);
}

#[test]
fn large_sections_enforce_answer_authority_additional_ranking_before_ttl_normalization() {
    let mut reply = response();
    reply.answers.push(address("www.example.", 60, 1));
    reply.authorities = fillers("authority");
    reply.authorities.extend([
        address("WWW.example.", 1, 2),
        address("ranked.example.", 50, 3),
    ]);
    reply.additionals = fillers("additional");
    reply.additionals.extend([
        address("www.EXAMPLE.", 2, 4),
        address("RANKED.example.", 2, 5),
    ]);
    assert!(normalize_response_rrsets(&mut reply, &question()));
    assert_eq!(reply.answers.last().unwrap().ttl, 60);
    assert_eq!(reply.authorities.len(), 41);
    assert_eq!(reply.authorities.last().unwrap().ttl, 50);
    assert_eq!(reply.additionals.len(), 40);
}

#[test]
fn large_sections_preserve_distinct_signatures_and_remove_only_exact_lower_ranked_ones() {
    let mut reply = response();
    reply.answers.extend([
        address("www.example.", 60, 1),
        signature(RecordType::A, 1, 60),
    ]);
    reply.authorities = fillers("authority");
    reply.authorities.extend([
        signature(RecordType::A, 1, 10),
        signature(RecordType::NS, 2, 30),
        signature(RecordType::NS, 3, 15),
    ]);
    reply.additionals = fillers("additional");
    reply.additionals.extend([
        signature(RecordType::NS, 2, 5),
        signature(RecordType::AAAA, 4, 45),
        signature(RecordType::AAAA, 4, 10),
    ]);
    assert!(normalize_response_rrsets(&mut reply, &question()));
    let authority_ttls: Vec<_> = reply
        .authorities
        .iter()
        .filter(|record| record.rtype == RecordType::RRSIG)
        .map(|record| record.ttl)
        .collect();
    let additional_ttls: Vec<_> = reply
        .additionals
        .iter()
        .filter(|record| record.rtype == RecordType::RRSIG)
        .map(|record| record.ttl)
        .collect();
    assert_eq!(authority_ttls, [30, 15]);
    assert_eq!(additional_ttls, [45]);
}

#[test]
fn large_same_owner_rrset_keeps_all_unique_records_in_order() {
    let mut reply = response();
    reply.answers = (0..2048)
        .map(|index| address("www.example.", 60, index))
        .collect();
    reply.answers.extend(reply.answers[1024..].to_vec());
    assert!(normalize_response_rrsets(&mut reply, &question()));
    assert_eq!(reply.answers.len(), 2048);
    for (index, record) in reply.answers.iter().enumerate() {
        assert_eq!(
            record.rdata,
            address("www.example.", 60, index as u32).rdata
        );
    }
}

#[test]
fn reserved_tsig_ttl_is_validated_instead_of_repaired_as_an_ordinary_ttl() {
    let mut reply = response();
    reply.answers.push(address("www.example.", 60, 1));
    reply.additionals.push(ResourceRecord {
        name: DomainName::from_dotted("key.example.").unwrap(),
        rtype: RecordType::TSIG,
        class: ClassType::Unknown(255),
        ttl: 0,
        rdata: RData::TSIG(dns::Tsig {
            algorithm: DomainName::from_dotted("hmac-sha256.").unwrap(),
            time_signed: 1,
            fudge: 300,
            mac: vec![0; 32],
            original_id: 0,
            error: dns::TsigErrorCode::NoError,
            other_data: Vec::new(),
        }),
    });
    assert!(normalize_response_rrsets(&mut reply, &question()));
    reply.additionals[0].ttl = 0x8000_0001;
    assert!(!normalize_response_rrsets(&mut reply, &question()));
    assert_eq!(reply.additionals[0].ttl, 0x8000_0001);
}

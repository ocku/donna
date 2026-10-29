use super::*;
use crate::cache::positive::PositiveCache;
use dns::{ClassType, Headers, IntoWire, Rrsig};
use std::time::Duration;

fn name(text: &str) -> DomainName {
    DomainName::from_dotted(text).unwrap()
}

fn record(owner: &str, rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name: name(owner),
        class: ClassType::IN,
        rtype,
        ttl: 60,
        rdata,
    }
}

fn cname(owner: &str, target: &str) -> ResourceRecord {
    record(owner, RecordType::CNAME, RData::CNAME(name(target)))
}

fn signature(owner: &str, covered: RecordType, labels: u8) -> ResourceRecord {
    record(
        owner,
        RecordType::RRSIG,
        RData::RRSIG(Rrsig {
            type_covered: u16::from(covered),
            algorithm: 15,
            labels,
            original_ttl: 60,
            signature_expiration: 2000000000,
            signature_inception: 1,
            key_tag: 1,
            signer_name: name("example."),
            signature: vec![7; 64],
        }),
    )
}

fn question() -> Question {
    Question {
        qname: name("Alias.Example."),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn message(answers: Vec<ResourceRecord>) -> Message {
    Message {
        headers: Headers {
            qr: true,
            ad: true,
            ..Headers::default()
        },
        questions: vec![question()],
        answers,
        authorities: vec![],
        additionals: vec![],
    }
}

fn assert_original(reply: Message, question: &Question) {
    let expected = cname_restart(&reply.answers, question);
    match (expected, cached_cname(reply.clone(), question)) {
        (Ok(Some((answers, target))), Ok(Some(actual))) => {
            assert_eq!(format!("{:?}", actual.answers), format!("{answers:?}"));
            assert_eq!(actual.target, target);
            assert_eq!(
                format!("{:?}", actual.authorities),
                format!("{:?}", wildcard_proofs(&reply, &answers))
            );
            assert_eq!(actual.authenticated, reply.headers.ad);
        }
        (Ok(None), Ok(None)) => {}
        (Err(expected), Err(actual)) => assert_eq!(actual, expected),
        _ => panic!("cached CNAME projection differs from original parser"),
    }
}

#[test]
fn admitted_cname_moves_exact_selected_records_and_wildcard_proofs() {
    for labels in [1, 2] {
        for authenticated in [false, true] {
            let mut reply = message(vec![
                signature("alias.example.", RecordType::CNAME, labels),
                cname("alias.example.", "Target.Example."),
                signature("alias.example.", RecordType::CNAME, labels),
            ]);
            if let RData::RRSIG(signature) = &mut reply.answers[2].rdata {
                signature.signature.fill(8);
            }
            reply.headers.ad = authenticated;
            reply.authorities = vec![
                record(
                    "a.example.",
                    RecordType::NSEC,
                    RData::NSEC(dns::Nsec {
                        next_domain_name: name("z.example."),
                        type_bitmap: dns::TypeBitmap::new([1, 46, 47]).unwrap(),
                    }),
                ),
                signature("a.example.", RecordType::NSEC, 2),
            ];
            let alias_question = Question {
                qtype: QueryType::CNAME,
                ..question()
            };
            let query = Message {
                headers: Headers::default(),
                questions: vec![alias_question.clone()],
                answers: vec![],
                authorities: vec![],
                additionals: vec![],
            };
            reply.questions.clone_from(&query.questions);
            reply.validate_for_forwarding().unwrap();
            let cache = PositiveCache::new(4);
            assert!(cache.insert(&query, &reply, Duration::from_secs(300)));
            let selected = cache.get_question(&alias_question).unwrap();
            assert_eq!(selected.authorities.len(), if labels == 1 { 2 } else { 0 });
            assert_original(selected.clone(), &question());
            let answers_pointer = selected.answers.as_ptr();
            let authorities_pointer = selected.authorities.as_ptr();
            let actual = cached_cname(selected, &question()).unwrap().unwrap();
            assert_eq!(answers_pointer, actual.answers.as_ptr());
            assert_eq!(authorities_pointer, actual.authorities.as_ptr());
            message(actual.answers).into_wire().unwrap();
        }
    }
}

#[test]
fn unusual_cached_shapes_keep_original_parser_results() {
    let first = cname("alias.example.", "target.example.");
    for answers in [
        vec![],
        vec![first.clone()],
        vec![cname("alias.example.", "ALIAS.EXAMPLE.")],
        vec![first.clone(), first.clone()],
        vec![first.clone(), cname("alias.example.", "other.example.")],
        vec![first.clone(), cname("target.example.", "end.example.")],
        vec![first.clone(), cname("target.example.", "alias.example.")],
        vec![
            signature("alias.example.", RecordType::CNAME, 1),
            first.clone(),
        ],
        vec![
            first.clone(),
            record(
                "alias.example.",
                RecordType::A,
                RData::A("192.0.2.1".parse().unwrap()),
            ),
        ],
        vec![first, signature("alias.example.", RecordType::TXT, 1)],
    ] {
        for qtype in [QueryType::A, QueryType::CNAME, QueryType::ANY] {
            for qclass in [
                QClassType::Class(ClassType::IN),
                QClassType::ANY,
                QClassType::Unknown(65400),
            ] {
                let question = Question {
                    qtype,
                    qclass,
                    ..question()
                };
                assert_original(message(answers.clone()), &question);
            }
        }
    }
}

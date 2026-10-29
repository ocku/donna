use super::*;

fn compare(message: &Message, ixfr: Option<&Question>) {
    let actual = super::super::encode_message_context(message, ixfr);
    let checked = super::super::encode_message_context_with_record_checks(message, ixfr, true);
    assert_eq!(actual, checked);
}

#[test]
fn reused_validation_matches_checked_encoding_for_sections_and_errors() {
    let owner = name(&[b"host", b"example", b"com"]);
    let base = ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::LOCALHOST),
    };
    for mutation in 0..7 {
        let mut record = base.clone();
        match mutation {
            0 => {}
            1 => record.ttl = u32::MAX,
            2 => record.class = ClassType::Unknown(1),
            3 => record.rtype = RecordType::Unknown(1),
            4 => {
                record.rtype = RecordType::TXT;
                record.rdata = RData::TXT(vec![]);
            }
            5 => {
                record.rtype = RecordType::NULL;
                record.rdata = RData::NULL(vec![0; 65536]);
            }
            6 => {
                record.rtype = RecordType::TXT;
                record.rdata = RData::TXT(vec![vec![0; 256]]);
            }
            _ => unreachable!(),
        }
        for section in 0..3 {
            let mut message = Message::builder()
                .headers(Headers {
                    qr: true,
                    ..Headers::default()
                })
                .questions([Question {
                    qname: owner.clone(),
                    qtype: QueryType::A,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build_unchecked();
            match section {
                0 => message.answers.push(record.clone()),
                1 => message.authorities.push(record.clone()),
                _ => message.additionals.push(record.clone()),
            }
            compare(&message, None);
            if mutation != 0 {
                assert!(message.into_wire().is_err());
            }
        }
    }
}

#[test]
fn specialized_update_notify_and_ixfr_validation_is_retained() {
    let update = super::update_and_header::update_message();
    let notify = notify_message();
    let mut ixfr = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: update_zone(),
            qtype: QueryType::IXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .answers([notify_soa(update_zone(), 2)])
        .build_unchecked();
    compare(&update, None);
    compare(&notify, None);
    compare(&ixfr, Some(&ixfr.questions[0]));
    assert!(update.into_wire().is_ok() && notify.into_wire().is_ok());
    assert!(ixfr.into_wire_ixfr(&ixfr.questions[0]).is_ok());
    for mut message in [update, notify] {
        message.additionals.push(ResourceRecord {
            name: DomainName::root(),
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::TXT(vec![]),
        });
        compare(&message, None);
        assert!(message.into_wire().is_err());
    }
    ixfr.answers[0].ttl = u32::MAX;
    compare(&ixfr, Some(&ixfr.questions[0]));
    assert!(ixfr.into_wire_ixfr(&ixfr.questions[0]).is_err());
}

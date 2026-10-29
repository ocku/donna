use super::*;

fn ordinary(
    request: &Message,
    answers: &[(&ResourceRecord, &DomainName)],
    authorities: &[&ResourceRecord],
) -> Message {
    let mut reply = Message::builder()
        .questions(request.questions.clone())
        .build()
        .unwrap();
    reply.headers = Headers {
        id: request.headers.id,
        qr: true,
        aa: true,
        rd: request.headers.rd,
        ..Headers::default()
    };
    reply.answers = answers
        .iter()
        .map(|&(record, owner)| {
            let mut record = record.clone();
            record.name = owner.clone();
            record
        })
        .collect();
    reply.authorities = authorities.iter().map(|&record| record.clone()).collect();
    if let Some(edns) = request.edns().unwrap() {
        reply.additionals.push(
            Edns {
                dnssec_ok: edns.dnssec_ok,
                ..Edns::default()
            }
            .into_record(),
        );
    }
    reply
}

fn a(owner: &DomainName, octet: u8) -> ResourceRecord {
    ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::A([192, 0, 2, octet].into()),
    }
}

#[test]
fn authoritative_projection_matches_structured_bytes_flags_case_binary_and_limits() {
    let source = name("*.EXAMPLE.test.");
    let address = a(&source, 1);
    let mut sig = signature(1);
    sig.name = source.clone();
    let mut proof = record(
        RecordType::NSEC,
        RData::NSEC(Nsec {
            next_domain_name: name("z.example.test."),
            type_bitmap: TypeBitmap::new([1, 47]).unwrap(),
        }),
    );
    proof.name = name("a.example.test.");
    for owner in [
        name("MiXeD.Example.test."),
        DomainName::from_labels(vec![
            vec![0, 255, b'A'],
            b"example".to_vec(),
            b"test".to_vec(),
        ])
        .unwrap(),
        DomainName::from_labels(vec![
            vec![b'A'; 63],
            vec![0; 63],
            vec![255; 63],
            vec![b'Z'; 48],
            b"example".to_vec(),
            b"test".to_vec(),
        ])
        .unwrap(),
    ] {
        for mode in 0..3 {
            for flags in 0..8 {
                let mut request = query();
                request.questions[0].qname = owner.clone();
                request.headers.rd = flags & 1 != 0;
                request.headers.ad = flags & 2 != 0;
                request.headers.cd = flags & 4 != 0;
                request.additionals = if mode == 0 {
                    vec![]
                } else {
                    vec![
                        Edns {
                            dnssec_ok: mode == 2,
                            ..Edns::new(1232)
                        }
                        .into_record(),
                    ]
                };
                let answers = if mode == 2 {
                    vec![(&address, &owner), (&sig, &owner)]
                } else {
                    vec![(&address, &owner)]
                };
                let authorities = if mode == 2 { vec![&proof] } else { vec![] };
                let expected = ordinary(&request, &answers, &authorities)
                    .into_wire()
                    .unwrap();
                let encoded =
                    EncodedReply::authoritative_positive(&request, &answers, &authorities, 1232)
                        .unwrap()
                        .unwrap();
                assert_eq!(encoded.as_bytes(), expected);
                assert!(encoded.matches_request(&request));
                // Correlation-limited replies retain full bytes; transport owns
                // complete-RRset truncation rather than this writer dropping RRs.
                let small =
                    EncodedReply::authoritative_positive(&request, &answers, &authorities, 32)
                        .unwrap()
                        .unwrap();
                assert_eq!(small.as_bytes(), expected);
            }
        }
    }
}

#[test]
fn authoritative_projection_retains_promoted_rrset_checks_and_effective_label_errors() {
    let source = name("long.source.owner.example.test.");
    let owner = name("m.example.test.");
    let mut request = query();
    request.questions[0].qname = owner.clone();
    for count in [2, 8, 9, 32, 33, 48] {
        let records = (1..=count).map(|n| a(&source, n as u8)).collect::<Vec<_>>();
        for mutation in 0..3 {
            let mut changed = records.clone();
            if mutation == 1 {
                changed[count - 1].rdata = changed[0].rdata.clone();
            }
            if mutation == 2 {
                changed[count - 1].ttl += 1;
            }
            let refs = changed
                .iter()
                .map(|record| (record, &owner))
                .collect::<Vec<_>>();
            let expected = ordinary(&request, &refs, &[]).into_wire();
            let actual = EncodedReply::authoritative_positive(&request, &refs, &[], 1232)
                .map(|reply| reply.unwrap().into_bytes());
            assert_eq!(actual, expected, "count={count} mutation={mutation}");
        }
    }
    let address = a(&source, 1);
    for labels in [3, 4, 5] {
        let mut sig = signature(1);
        sig.name = source.clone();
        if let RData::RRSIG(value) = &mut sig.rdata {
            value.labels = labels;
        }
        let refs = [(&address, &owner), (&sig, &owner)];
        assert_eq!(
            EncodedReply::authoritative_positive(&request, &refs, &[], 1232)
                .map(|reply| reply.unwrap().into_bytes()),
            ordinary(&request, &refs, &[]).into_wire()
        );
    }
}

#[test]
fn authoritative_projection_declines_unsupported_owner_and_request_policies() {
    let source = name("source.example.test.");
    let owner = name("m.example.test.");
    let mut request = query();
    request.questions[0].qname = owner.clone();
    let first = a(&source, 1);
    let other = a(&name("other.example.test."), 2);
    assert!(
        EncodedReply::authoritative_positive(
            &request,
            &[(&first, &owner), (&other, &owner)],
            &[],
            1232
        )
        .unwrap()
        .is_none()
    );
    for collision in [&source, &owner] {
        let mut proof = record(
            RecordType::NSEC,
            RData::NSEC(Nsec {
                next_domain_name: name("z.example.test."),
                type_bitmap: TypeBitmap::new([47]).unwrap(),
            }),
        );
        proof.name = collision.clone();
        assert!(
            EncodedReply::authoritative_positive(&request, &[(&first, &owner)], &[&proof], 1232)
                .unwrap()
                .is_none()
        );
    }
    for mutation in 0..8 {
        let mut changed = request.clone();
        match mutation {
            0 => changed.headers.qr = true,
            1 => changed.headers.aa = true,
            2 => changed.headers.ra = true,
            3 => changed.headers.tc = true,
            4 => changed.questions[0].qclass = QClassType::ANY,
            5 => changed.additionals.push(changed.additionals[0].clone()),
            6 => {
                if let RData::OPT(options) = &mut changed.additionals[0].rdata {
                    options.push(crate::EdnsOption {
                        code: 65000,
                        data: vec![1],
                    });
                }
            }
            _ => changed.additionals[0].ttl |= 1 << 16,
        }
        assert!(
            EncodedReply::authoritative_positive(&changed, &[(&first, &owner)], &[], 1232)
                .unwrap()
                .is_none(),
            "mutation={mutation}"
        );
    }
}

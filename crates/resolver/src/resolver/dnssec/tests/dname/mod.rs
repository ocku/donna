mod cache;
mod provenance;
mod republication;
mod terminal_regression;
mod zero;

use super::{
    fixtures::{resolver, signed_record_fixture},
    support::name,
};
use dns::{
    ClassType, DnssecSecurityStatus, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};

#[tokio::test]
async fn authenticated_dname_binds_only_matching_synthesized_cname_and_its_ttl() {
    for (corrupt, forged, ttl, dname_ttl) in [
        (false, false, 900, 900),
        (false, false, 900, 2),
        (false, false, 0, 900),
        (true, false, 900, 900),
        (false, true, 900, 900),
    ] {
        let owner = name(&["old", "example"]);
        let destination = name(&["new", "other"]);
        let (transport, anchor, _) = signed_record_fixture(
            corrupt,
            owner,
            QueryType::DNAME,
            RecordType::DNAME,
            RData::DNAME(destination),
        );
        let mut reply = transport.answer.clone();
        reply.answers[0].ttl = dname_ttl;
        let q = Question {
            qname: name(&["www", "old", "example"]),
            qtype: QueryType::CNAME,
            qclass: QClassType::Class(ClassType::IN),
        };
        let target = if forged {
            name(&["wrong", "other"])
        } else {
            name(&["www", "new", "other"])
        };
        reply.questions = vec![q.clone()];
        reply.answers.push(ResourceRecord {
            name: q.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl,
            rdata: RData::CNAME(target),
        });
        let resolver = resolver(transport, anchor);
        if !corrupt && !forged && ttl != 0 {
            let mut signed_synthetic = reply.clone();
            let mut bad_signature = signed_synthetic.answers[1].clone();
            bad_signature.name = q.qname.clone();
            let RData::RRSIG(signature) = &mut bad_signature.rdata else {
                unreachable!()
            };
            signature.type_covered = u16::from(RecordType::CNAME);
            signed_synthetic.answers.push(bad_signature);
            assert!(
                resolver
                    .validate_dnssec_response(&q, &mut signed_synthetic)
                    .await
                    .is_err()
            );
        }
        let result = resolver.validate_dnssec_response(&q, &mut reply).await;
        if corrupt || forged {
            assert!(result.is_err(), "corrupt={corrupt}, forged={forged}");
        } else {
            assert!(matches!(result, Ok(DnssecSecurityStatus::Secure)));
            let derived = reply
                .answers
                .iter()
                .find(|rr| rr.rtype == RecordType::CNAME)
                .unwrap();
            let dname = reply
                .answers
                .iter()
                .find(|rr| rr.rtype == RecordType::DNAME)
                .unwrap();
            assert!(derived.ttl <= dname.ttl);
            assert!(derived.ttl <= dname_ttl);
            if ttl == 0 {
                assert_eq!(derived.ttl, 0);
            }
        }
    }
}

#[tokio::test]
async fn overflowing_dname_proof_can_be_authenticated_without_a_cname() {
    use dns::{DomainName, RCode};
    let destination = DomainName::from_labels(vec![
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 60],
    ])
    .unwrap();
    for corrupt in [false, true] {
        let (transport, anchor, _) = signed_record_fixture(
            corrupt,
            name(&["old", "example"]),
            QueryType::DNAME,
            RecordType::DNAME,
            RData::DNAME(destination.clone()),
        );
        let mut reply = transport.answer.clone();
        let question = Question {
            qname: name(&["prefix", "old", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        reply.questions = vec![question.clone()];
        reply.headers.rcode = RCode::YXDomain;
        let resolver = resolver(transport, anchor);
        let result = resolver
            .validate_dnssec_response(&question, &mut reply)
            .await;
        if corrupt {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(DnssecSecurityStatus::Secure)));
        }
    }
}

#[tokio::test]
async fn signed_dname_to_nxdomain_validates_alias_and_terminal_denial() {
    use super::{negative::negative_fixture, support::TestRng};
    use rsa::pkcs8::EncodePrivateKey;
    let (transport, anchor, _) = negative_fixture();
    let mut rng = TestRng(0xabcd_ef01_2345_6789);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = dns::RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let zone = name(&["example"]);
    let owner = name(&["old", "example"]);
    let dname = ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 90,
        rdata: RData::DNAME(zone.clone()),
    };
    let now = super::super::records::unix_time();
    let sign = |rr: &ResourceRecord| {
        key.sign_rrset(
            std::slice::from_ref(rr),
            &zone,
            now.wrapping_sub(60),
            now + 3600,
        )
        .unwrap()
    };
    let sig = |owner, signature| ResourceRecord {
        name: owner,
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl: 90,
        rdata: RData::RRSIG(signature),
    };
    let mut reply = transport.answer.clone();
    let nsec = reply
        .authorities
        .iter_mut()
        .find(|rr| rr.rtype == RecordType::NSEC)
        .unwrap();
    let RData::NSEC(value) = &mut nsec.rdata else {
        unreachable!()
    };
    value.next_domain_name = owner.clone();
    let nsec = nsec.clone();
    let nsec_sig = reply
        .authorities
        .iter_mut()
        .find(|rr| matches!(&rr.rdata, RData::RRSIG(value) if value.type_covered == 47))
        .unwrap();
    nsec_sig.rdata = RData::RRSIG(sign(&nsec));
    let question = Question {
        qname: name(&["missing", "old", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    reply.questions = vec![question.clone()];
    reply.answers = vec![
        dname.clone(),
        sig(owner, sign(&dname)),
        ResourceRecord {
            name: question.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 90,
            rdata: RData::CNAME(name(&["missing", "example"])),
        },
    ];
    let resolver = resolver(transport, anchor);
    let mut valid = reply.clone();
    assert!(matches!(
        resolver
            .validate_dnssec_response(&question, &mut valid)
            .await,
        Ok(DnssecSecurityStatus::Secure)
    ));
    let mut forged = reply.clone();
    forged.answers[2].rdata = RData::CNAME(name(&["forged", "example"]));
    assert!(
        resolver
            .validate_dnssec_response(&question, &mut forged)
            .await
            .is_err()
    );
    let mut bad_denial = reply;
    bad_denial
        .authorities
        .retain(|rr| rr.rtype != RecordType::NSEC);
    assert!(
        resolver
            .validate_dnssec_response(&question, &mut bad_denial)
            .await
            .is_err()
    );
}

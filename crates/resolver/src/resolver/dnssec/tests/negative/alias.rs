//! NXDOMAIN cuts belong to a signed alias chain's terminal denied owner.
use super::super::{
    fixtures::resolver,
    negative::negative_fixture,
    support::{TestRng, name},
};
use dns::{ClassType, QueryType, Question, RCode, RData, RecordType, ResourceRecord};
use rsa::pkcs8::EncodePrivateKey;

#[tokio::test]
async fn aggressive_negative_signed_aliases_preserve_answers_and_only_cut_the_terminal_owner() {
    let mut rng = TestRng(0xabcd_ef01_2345_6789);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = dns::RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    for dname in [false, true] {
        let (mut transport, anchor, terminal) = negative_fixture();
        let zone = name(&["example"]);
        let owner = name(&["old", "example"]);
        let now = super::super::super::unix_time();
        let sign = |record: &ResourceRecord| ResourceRecord {
            name: record.name.clone(),
            rtype: RecordType::RRSIG,
            class: ClassType::IN,
            ttl: 90,
            rdata: RData::RRSIG(
                key.sign_rrset(
                    std::slice::from_ref(record),
                    &zone,
                    now.wrapping_sub(60),
                    now + 3600,
                )
                .unwrap(),
            ),
        };
        // End the denial interval at the existing alias owner, so the proof
        // denies missing.example without denying the alias's existence.
        let proof = transport
            .answer
            .authorities
            .iter_mut()
            .find(|rr| rr.rtype == RecordType::NSEC)
            .unwrap();
        let RData::NSEC(nsec) = &mut proof.rdata else {
            unreachable!()
        };
        nsec.next_domain_name = owner.clone();
        let signature = sign(proof);
        let old_sig = transport
            .answer
            .authorities
            .iter_mut()
            .find(|rr| matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == 47))
            .unwrap();
        *old_sig = signature;
        let alias = ResourceRecord {
            name: owner.clone(),
            rtype: if dname {
                RecordType::DNAME
            } else {
                RecordType::CNAME
            },
            class: ClassType::IN,
            ttl: 90,
            rdata: if dname {
                RData::DNAME(zone.clone())
            } else {
                RData::CNAME(terminal.qname.clone())
            },
        };
        let question = Question {
            qname: if dname {
                name(&["missing", "old", "example"])
            } else {
                owner
            },
            ..terminal.clone()
        };
        transport.answer.questions = vec![question.clone()];
        transport.answer.answers = vec![alias.clone(), sign(&alias)];
        if dname {
            transport.answer.answers.push(ResourceRecord {
                name: question.qname.clone(),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 90,
                rdata: RData::CNAME(terminal.qname.clone()),
            });
        }
        transport.answer.authorities.push(ResourceRecord {
            name: name(&["example"]),
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 300,
            rdata: RData::NS(name(&["unsigned", "example"])),
        });
        let expected = transport.answer.answers.clone();
        let resolver = resolver(transport, anchor);
        let address = (std::net::Ipv4Addr::LOCALHOST, 53).into();
        resolver.delegation_cache.insert(
            &crate::protocol::Referral {
                zone: name(&["example"]),
                class: ClassType::IN,
                candidates: vec![address],
                candidate_ttls: vec![(address, std::time::Duration::from_secs(60))],
                trusted_glue: vec![],
                name_servers: vec![name(&["ns", "example"])],
                ttl: std::time::Duration::from_secs(60),
            },
            std::time::Duration::from_secs(60),
        );
        let fresh = resolver.resolve(question.clone()).await.unwrap();
        assert!(fresh.headers.ad);
        assert_eq!(fresh.headers.rcode, RCode::NameError);
        assert_eq!(fresh.answers.len(), expected.len());
        assert!(
            fresh
                .answers
                .iter()
                .zip(&expected)
                .all(|(actual, expected)| actual.eq_dns(expected) && actual.ttl <= expected.ttl)
        );
        assert!(
            !fresh
                .authorities
                .iter()
                .any(|rr| rr.rtype == RecordType::NS)
        );
        assert!(
            resolver.negative_cache.get(&question).is_none(),
            "source alias exists"
        );
        let source_child = Question {
            qname: if dname {
                name(&["child", "missing", "old", "example"])
            } else {
                name(&["child", "old", "example"])
            },
            ..question
        };
        assert!(
            resolver
                .negative_cache
                .select_name_error_ancestor(&source_child)
                .is_none()
        );
        let denied_child = Question {
            qname: name(&["child", "missing", "example"]),
            qtype: QueryType::AAAA,
            ..terminal
        };
        let cut = resolver
            .cached_client_response(&denied_child)
            .unwrap()
            .unwrap()
            .response;
        assert!(cut.headers.ad);
        assert_eq!(cut.headers.rcode, RCode::NameError);
        assert!(
            cut.answers.is_empty(),
            "terminal-only cache projection needs no prior alias"
        );
    }
}

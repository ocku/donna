use super::*;
use dns::{ClassType, DomainName, RData, RecordType, ResourceRecord};

#[test]
fn delayed_follower_never_renews_ttls_or_edns_flags() {
    let at = Instant::now();
    let mut response = Message::builder().build().unwrap();
    response.answers.push(ResourceRecord {
        name: DomainName::from_dotted("example.").unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 5,
        rdata: RData::A([192, 0, 2, 1].into()),
    });
    response.additionals.push(ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::OPT,
        class: ClassType::Unknown(1232),
        ttl: 0x01008000,
        rdata: RData::OPT(vec![]),
    });
    age_response(&mut response, at, at + Duration::from_millis(2200));
    assert_eq!(response.answers[0].ttl, 2);
    assert_eq!(response.additionals[0].ttl, 0x01008000);
    age_response(&mut response, at, at + Duration::from_secs(6));
    assert_eq!(response.answers[0].ttl, 0);
}

#[tokio::test]
async fn delayed_entry_follower_receives_expired_a_and_dname() {
    let entry = InFlightEntry::new();
    let mut response = Message::builder().build().unwrap();
    let owner = DomainName::from_dotted("old.example.").unwrap();
    response.answers.push(ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 3,
        rdata: RData::DNAME(DomainName::from_dotted("new.example.").unwrap()),
    });
    response.answers.push(ResourceRecord {
        name: DomainName::from_dotted("new.example.").unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 4,
        rdata: RData::A([192, 0, 2, 1].into()),
    });
    let published = Instant::now() - Duration::from_secs(5);
    entry.state.send_replace(InFlightState::Succeeded(
        Arc::new(response),
        published,
        Some(published + Duration::from_secs(3)),
        Arc::from([]),
    ));
    let (received, deadline, _) = entry.wait().await.unwrap();
    assert!(received.answers.iter().all(|record| record.ttl == 0));
    assert!(deadline.unwrap() <= Instant::now());
}

#[tokio::test]
async fn signed_transaction_follower_reissues_instead_of_reusing() {
    let key_name = DomainName::from_dotted("key.example.").unwrap();
    let sigs = vec![
        ResourceRecord {
            name: key_name.clone(),
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
        },
        ResourceRecord {
            name: DomainName::root(),
            rtype: RecordType::SIG,
            class: ClassType::Unknown(255),
            ttl: 0,
            rdata: RData::SIG(dns::Sig {
                type_covered: 0,
                algorithm: 8,
                labels: 0,
                original_ttl: 0,
                signature_expiration: 100,
                signature_inception: 1,
                key_tag: 1,
                signer_name: key_name,
                signature: vec![1],
            }),
        },
    ];
    let question = Question {
        qname: DomainName::from_dotted("www.example.").unwrap(),
        qtype: dns::QueryType::A,
        qclass: dns::QClassType::Class(ClassType::IN),
    };
    for signature in sigs {
        let table = InFlightTable::new(4);
        let key = InFlightKey::new(&question, &AlgorithmSignals::default());
        let Admission::Leader(leader) = table.admit(key.clone()) else {
            panic!("leader")
        };
        let Admission::Follower(follower) = table.admit(key.clone()) else {
            panic!("follower")
        };
        let mut response = Message::builder().build().unwrap();
        response.additionals.push(signature);
        leader.succeed(&response, None, &[]);
        assert!(follower.wait().await.is_none());
        assert!(matches!(table.admit(key), Admission::Leader(_)));
    }
}

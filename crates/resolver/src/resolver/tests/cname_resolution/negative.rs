use super::*;

#[tokio::test]
async fn cross_zone_cname_negative_does_not_replace_direct_authoritative_negative() {
    let target = question(&["missing", "other"]);
    let alias = question(&["www", "example"]);
    let mut direct = response(
        Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        Vec::new(),
    );
    direct.authorities = vec![soa_record(name(&["other"]), 60, 30)];

    let mut replacement_soa = soa_record(name(&["other"]), 30, 30);
    let RData::SOA { serial, .. } = &mut replacement_soa.rdata else {
        unreachable!("the helper creates an SOA")
    };
    *serial = 2;
    let mut derived = response(
        Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        vec![ResourceRecord {
            name: alias.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CNAME(target.qname.clone()),
        }],
    );
    derived.authorities = vec![replacement_soa];
    derived.questions = vec![alias.clone()];
    // Exercise the actual transport representation: strict publication must
    // validate the SOA against the final CNAME target, and the receiver must
    // recover the same terminal negative response from the wire.
    let derived = Message::from_wire(&derived.into_wire().unwrap()).unwrap();

    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![direct, derived])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    resolver.resolve(target.clone()).await.unwrap();
    let cross_zone = resolver.resolve(alias).await.unwrap();
    assert!(cross_zone.into_wire().is_ok());
    let cached = resolver.resolve(target).await.unwrap();

    assert!(matches!(
        cached.authorities[0].rdata,
        RData::SOA { serial: 1, .. }
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn caches_soa_backed_nodata_with_answer_signatures() {
    let query = question(&["signed", "example"]);
    let mut nodata = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![
            ResourceRecord {
                name: query.qname.clone(),
                rtype: RecordType::SIG,
                class: ClassType::IN,
                ttl: 20,
                rdata: RData::SIG(dns::Sig {
                    type_covered: 1,
                    algorithm: 1,
                    labels: 2,
                    original_ttl: 20,
                    signature_expiration: 2,
                    signature_inception: 1,
                    key_tag: 1,
                    signer_name: DomainName::root(),
                    signature: vec![1],
                }),
            },
            ResourceRecord {
                name: query.qname.clone(),
                rtype: RecordType::RRSIG,
                class: ClassType::IN,
                ttl: 10,
                rdata: RData::RRSIG(dns::Rrsig {
                    type_covered: u16::from(RecordType::A),
                    algorithm: 15,
                    labels: 2,
                    original_ttl: 10,
                    signature_expiration: 2,
                    signature_inception: 1,
                    key_tag: 1,
                    signer_name: name(&["example"]),
                    signature: vec![2],
                }),
            },
        ],
    );
    nodata.authorities = vec![soa_record(name(&["example"]), 60, 30)];
    let transport = MockTransport {
        replies: Arc::new(Mutex::new(vec![nodata])),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(transport, config(vec!["192.0.2.53:53".parse().unwrap()]));

    let first = resolver.resolve(query.clone()).await.unwrap();
    let cached = resolver.resolve(query).await.unwrap();

    assert_eq!(first.answers.len(), 2);
    assert!(cached.answers.is_empty());
    assert_eq!(cached.authorities.len(), 1);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

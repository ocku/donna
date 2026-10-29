use super::*;

fn name(value: &str) -> DomainName {
    DomainName::from_dotted(value).unwrap()
}

#[test]
fn constructs_browse_resolve_subtype_and_enumeration_names() {
    let service = ServiceType::new("http", ServiceTransport::Tcp).unwrap();
    let domain = name("local");
    assert_eq!(service.owner(&domain).unwrap(), name("_http._tcp.local"));
    assert_eq!(
        service.subtype_owner("printer", &domain).unwrap(),
        name("_printer._sub._http._tcp.local")
    );
    assert_eq!(
        service_enumeration_name(&domain).unwrap(),
        name("_services._dns-sd._udp.local")
    );
    let instance = ServiceInstance::new(b"Office".to_vec(), service, domain).unwrap();
    assert_eq!(instance.owner().unwrap(), name("Office._http._tcp.local"));
    assert_eq!(
        instance.renamed(2).unwrap().owner().unwrap(),
        name("Office (2)._http._tcp.local")
    );
}

#[test]
fn parses_txt_keys_case_insensitively_and_ignores_later_duplicates() {
    assert_eq!(
        parse_service_txt(&[b"path=/status".to_vec(), b"flag".to_vec()]).unwrap(),
        vec![
            TxtProperty {
                key: b"path".to_vec(),
                value: Some(b"/status".to_vec()),
            },
            TxtProperty {
                key: b"flag".to_vec(),
                value: None,
            }
        ]
    );
    assert_eq!(
        parse_service_txt(&[Vec::new(), b"Path=a".to_vec(), b"path=b".to_vec()]).unwrap(),
        vec![TxtProperty {
            key: b"Path".to_vec(),
            value: Some(b"a".to_vec())
        }]
    );
}

#[test]
fn browses_and_resolves_an_mdns_service_with_addresses() {
    let service = ServiceType::new("http", ServiceTransport::Tcp).unwrap();
    let domain = name("local");
    let browse = service.owner(&domain).unwrap();
    let instance = name("Office._http._tcp.local");
    let target = name("office.local");
    let records = vec![
        ResourceRecord {
            name: browse,
            rtype: RecordType::PTR,
            class: ClassType::IN,
            ttl: 4_500,
            rdata: RData::PTR(instance.clone()),
        },
        ResourceRecord {
            name: instance.clone(),
            rtype: RecordType::SRV,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::SRV {
                priority: 0,
                weight: 0,
                port: 8080,
                target: target.clone(),
            },
        },
        ResourceRecord {
            name: instance,
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::TXT(vec![b"path=/".to_vec()]),
        },
        ResourceRecord {
            name: target,
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 44)),
        },
    ];
    let resolved =
        resolve_services(&service, &domain, &records, DiscoverySecurity::LocalLink).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].port, 8080);
    assert_eq!(resolved[0].ipv4_addresses, [Ipv4Addr::new(192, 0, 2, 44)]);
}

#[test]
fn discovery_uses_only_internet_class_records() {
    let service = ServiceType::new("http", ServiceTransport::Tcp).unwrap();
    let domain = name("local");
    let instance = name("Office._http._tcp.local");
    let target = name("office.local");
    let in_records = vec![
        ResourceRecord {
            name: service.owner(&domain).unwrap(),
            rtype: RecordType::PTR,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::PTR(instance.clone()),
        },
        ResourceRecord {
            name: instance.clone(),
            rtype: RecordType::SRV,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::SRV {
                priority: 0,
                weight: 0,
                port: 8080,
                target: target.clone(),
            },
        },
        ResourceRecord {
            name: instance,
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::TXT(vec![b"path=/".to_vec()]),
        },
        ResourceRecord {
            name: target.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 44)),
        },
        ResourceRecord {
            name: target,
            rtype: RecordType::AAAA,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::AAAA("2001:db8::1".parse().unwrap()),
        },
    ];
    let mut foreign = in_records.clone();
    for record in &mut foreign {
        record.class = ClassType::CH;
        match &mut record.rdata {
            RData::SRV { port, .. } => *port = 9999,
            RData::TXT(strings) => *strings = vec![b"=malformed".to_vec()],
            RData::A(address) => *address = Ipv4Addr::new(192, 0, 2, 99),
            RData::AAAA(address) => *address = "2001:db8::99".parse().unwrap(),
            _ => {}
        }
    }
    assert!(
        resolve_services(&service, &domain, &foreign, DiscoverySecurity::LocalLink)
            .unwrap()
            .is_empty()
    );
    foreign.extend(in_records);
    let resolved =
        resolve_services(&service, &domain, &foreign, DiscoverySecurity::LocalLink).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].port, 8080);
    assert_eq!(resolved[0].txt[0].value.as_deref(), Some(b"/".as_slice()));
    assert_eq!(resolved[0].ipv4_addresses, [Ipv4Addr::new(192, 0, 2, 44)]);
    assert_eq!(
        resolved[0].ipv6_addresses,
        ["2001:db8::1".parse::<Ipv6Addr>().unwrap()]
    );
}

#[test]
fn unavailable_srv_target_produces_no_resolved_service() {
    let service = ServiceType::new("http", ServiceTransport::Tcp).unwrap();
    let domain = name("local");
    let instance = name("Office._http._tcp.local");
    let records = vec![
        ResourceRecord {
            name: service.owner(&domain).unwrap(),
            rtype: RecordType::PTR,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::PTR(instance.clone()),
        },
        ResourceRecord {
            name: instance.clone(),
            rtype: RecordType::SRV,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::SRV {
                priority: 0,
                weight: 0,
                port: 80,
                target: name("."),
            },
        },
        // Neither malformed TXT nor stale addresses may manufacture an
        // endpoint or turn the explicit unavailable signal into an error.
        ResourceRecord {
            name: instance,
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::TXT(vec![b"=malformed".to_vec()]),
        },
        ResourceRecord {
            name: name("."),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 44)),
        },
    ];
    assert!(
        resolve_services(&service, &domain, &records, DiscoverySecurity::LocalLink)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn service_names_reject_consecutive_hyphens() {
    assert_eq!(
        ServiceType::new("a--b", ServiceTransport::Tcp),
        Err(DnsSdError::InvalidServiceType)
    );
    assert!(ServiceType::new("a-b", ServiceTransport::Tcp).is_ok());
}

#[test]
fn raw_subtype_labels_preserve_arbitrary_octets_and_optional_underscore() {
    let service = ServiceType::new("http", ServiceTransport::Tcp).unwrap();
    let domain = name("local");
    for label in [
        b"printer".to_vec(),
        b"_printer".to_vec(),
        b"a b".to_vec(),
        "café".as_bytes().to_vec(),
        vec![0, 0xff, b'.'],
        vec![b'a'; 63],
    ] {
        let owner = service.subtype_owner_label(&label, &domain).unwrap();
        assert_eq!(owner.as_ref()[0], label);
        assert_eq!(owner.as_ref()[1], b"_sub");
    }
    for label in [Vec::new(), vec![b'a'; 64]] {
        assert_eq!(
            service.subtype_owner_label(&label, &domain),
            Err(DnsSdError::InvalidSubtype)
        );
    }
    assert_eq!(
        service.subtype_owner("_printer", &domain).unwrap(),
        name("_printer._sub._http._tcp.local")
    );
    assert_eq!(
        service.subtype_owner("a b", &domain).unwrap().as_ref()[0],
        b"_a b"
    );
}

#[test]
fn instance_labels_require_net_unicode_and_normalize_before_length_check() {
    let service = ServiceType::new("http", ServiceTransport::Tcp).unwrap();
    let domain = name("local");
    let instance = ServiceInstance::new("Cafe\u{301}", service.clone(), domain.clone()).unwrap();
    assert_eq!(instance.instance_label, "Café".as_bytes());
    assert!(ServiceInstance::new("e\u{301}".repeat(31), service.clone(), domain.clone()).is_ok());
    for label in ["A café. 東京!", &"a".repeat(63)] {
        assert!(ServiceInstance::new(label, service.clone(), domain.clone()).is_ok());
    }
    let mut invalid = vec![vec![0xff], Vec::new(), vec![b'a'; 64]];
    for control in (0u8..=31).chain([127]) {
        invalid.push(vec![b'a', control]);
    }
    for text in ["\u{80}", "\u{9f}", "\u{feff}name", "\u{0378}", "\u{ffff}"] {
        invalid.push(text.as_bytes().to_vec());
    }
    for label in invalid {
        assert_eq!(
            ServiceInstance::new(label.clone(), service.clone(), domain.clone()),
            Err(DnsSdError::InvalidInstanceLabel)
        );
        let mut mutated = instance.clone();
        mutated.instance_label = label;
        assert_eq!(mutated.owner(), Err(DnsSdError::InvalidInstanceLabel));
    }
    let mut mutated = instance;
    mutated.instance_label = "Cafe\u{301}".as_bytes().to_vec();
    assert_eq!(mutated.owner(), Err(DnsSdError::InvalidInstanceLabel));
}

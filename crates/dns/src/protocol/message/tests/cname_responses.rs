use super::*;

fn cname_response() -> Message {
    let alias = DomainName::from_dotted("alias.example.").unwrap();
    Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: alias.clone(),
            qtype: QueryType::A,
            qclass: crate::QClassType::Class(crate::ClassType::IN),
        }])
        .answers([ResourceRecord {
            name: alias,
            rtype: RecordType::CNAME,
            class: crate::ClassType::IN,
            ttl: 30,
            rdata: crate::RData::CNAME(DomainName::from_dotted("target.outside.").unwrap()),
        }])
        .build_unchecked()
}

fn soa(owner: &str) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_dotted(owner).unwrap(),
        rtype: RecordType::SOA,
        class: crate::ClassType::IN,
        ttl: 30,
        rdata: crate::RData::SOA {
            mname: DomainName::root(),
            rname: DomainName::root(),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 30,
        },
    }
}

#[test]
fn authoritative_incomplete_cname_is_encodable_without_claiming_target_nodata() {
    let mut response = cname_response();
    assert!(response.clone().into_wire().is_ok());
    response.authorities.push(ResourceRecord {
        name: DomainName::from_dotted("outside.").unwrap(),
        rtype: RecordType::NS,
        class: crate::ClassType::IN,
        ttl: 30,
        rdata: crate::RData::NS(DomainName::from_dotted("ns.outside.").unwrap()),
    });
    assert!(response.into_wire().is_ok());
}

#[test]
fn cname_terminal_negative_still_requires_correct_soa_scope_class_and_ttl() {
    let mut response = cname_response();
    response.authorities.push(soa("outside."));
    assert!(response.clone().into_wire().is_ok());
    for invalid in [
        soa("example."),
        ResourceRecord {
            ttl: 31,
            ..soa("outside.")
        },
        ResourceRecord {
            class: crate::ClassType::CH,
            ..soa("outside.")
        },
    ] {
        response.authorities = vec![invalid];
        assert_eq!(
            response.validate_strict(),
            Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
        );
    }
    response.authorities.clear();
    response.headers.rcode = RCode::NameError;
    assert_eq!(
        response.validate_strict(),
        Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
    );
    response.headers.rcode = RCode::Ok;
    response.answers.clear();
    assert_eq!(
        response.validate_strict(),
        Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
    );
}

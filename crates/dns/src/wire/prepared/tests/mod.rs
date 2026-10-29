use super::*;
use crate::{ClassType, DomainName, Headers, Nsec, Rrsig, TypeBitmap};

mod authoritative_positive;
mod borrowed;
mod positive;
mod recursive;

fn name(text: &str) -> DomainName {
    DomainName::from_dotted(text).unwrap()
}

fn record(rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name: name("example.test."),
        rtype,
        class: ClassType::IN,
        ttl: 30,
        rdata,
    }
}

fn signature(covered: u16) -> ResourceRecord {
    record(
        RecordType::RRSIG,
        RData::RRSIG(Rrsig {
            type_covered: covered,
            algorithm: 15,
            labels: 2,
            original_ttl: 30,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: name("example.test."),
            signature: vec![covered as u8; 64],
        }),
    )
}

fn query() -> Message {
    Message::builder()
        .headers(Headers {
            id: 7,
            rd: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: name("missing.example.test."),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([Edns {
            dnssec_ok: true,
            ..Edns::new(1232)
        }
        .into_record()])
        .build()
        .unwrap()
}

fn reply() -> Message {
    let mut response = query();
    response.headers.qr = true;
    response.headers.ra = true;
    response.headers.ad = true;
    response.headers.rcode = RCode::NameError;
    response.authorities = vec![
        record(
            RecordType::SOA,
            RData::SOA {
                mname: name("ns.example.test."),
                rname: name("hostmaster.example.test."),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 30,
            },
        ),
        record(
            RecordType::NSEC,
            RData::NSEC(Nsec {
                next_domain_name: name("next.example.test."),
                type_bitmap: TypeBitmap::new([6, 46, 47]).unwrap(),
            }),
        ),
        signature(6),
        signature(47),
    ];
    response
}

fn ns() -> ResourceRecord {
    record(RecordType::NS, RData::NS(name("NS.example.test.")))
}

mod name_servers;
mod negative;

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::constants::header::HEADER_OCTETS;
use crate::wire::{Decoder, decode_name};
use crate::{
    ClassType, DomainName, FromWire, Headers, IntoWire, Message, MessageValidationError,
    QClassType, QueryType, Question, RData, RecordType, ResourceRecord,
};

fn name(labels: &[&[u8]]) -> DomainName {
    DomainName::from_labels(labels.iter().map(|label| label.to_vec()).collect()).unwrap()
}

fn update_zone() -> DomainName {
    name(&[b"example", b"com"])
}

fn update_meta(owner: DomainName, rtype: RecordType, class: u16) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype,
        class: ClassType::Unknown(class),
        ttl: 0,
        rdata: RData::Unknown(Vec::new()),
    }
}

fn notify_soa(zone: DomainName, serial: u32) -> ResourceRecord {
    ResourceRecord {
        name: zone,
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl: 300,
        rdata: RData::SOA {
            mname: name(&[b"primary", b"example", b"com"]),
            rname: name(&[b"hostmaster", b"example", b"com"]),
            serial,
            refresh: 3600,
            retry: 600,
            expire: 86_400,
            minimum: 300,
        },
    }
}

fn notify_message() -> Message {
    let zone = update_zone();
    Message::builder()
        .headers(Headers {
            id: 0x1996,
            opcode: crate::OpCode::Notify,
            aa: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: zone.clone(),
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .answers([notify_soa(zone, 2)])
        .build()
        .unwrap()
}

mod compression_and_limits;
mod name_pointer_limits;
mod notify;
mod record_round_trips;
mod singleton_sections;
mod update_and_header;
mod validation_reuse;

use super::*;
use dns::{ClassType, DomainName, QClassType, QueryType, RData, RecordType};
use std::net::Ipv4Addr;

fn question(id: u16) -> Message {
    Message::builder()
        .headers(Headers {
            id,
            rd: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"WWW".to_vec(), b"example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

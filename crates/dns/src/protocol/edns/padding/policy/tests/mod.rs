use crate::{
    ClassType, DomainName, EDNS_EXTENDED_DNS_ERROR_OPTION_CODE, EDNS_PADDING_OPTION_CODE, Edns,
    EdnsOption, Headers, QClassType, QueryType, Question, RecordValidationError,
};

use super::*;

fn query() -> Message {
    Message::builder()
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([Edns::new(1232).into_record()])
        .build()
        .unwrap()
}

fn response() -> Message {
    Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .questions(query().questions)
        .additionals([Edns::new(1232).into_record()])
        .build()
        .unwrap()
}

fn set_edns_options(message: &mut Message, options: Vec<EdnsOption>) {
    let mut edns = message.edns().unwrap().unwrap();
    edns.options = options;
    message.additionals[0] = edns.into_record();
}

fn assert_outcome_matches_wire(message: &Message, outcome: PaddingOutcome, block_size: usize) {
    let encoded_octets = message.into_wire().unwrap().len();
    match outcome {
        PaddingOutcome::Padded {
            message_octets,
            block_aligned,
            ..
        } => {
            assert_eq!(message_octets, encoded_octets);
            assert_eq!(block_aligned, encoded_octets.is_multiple_of(block_size));
        }
        PaddingOutcome::OmittedInsufficientSpace { message_octets } => {
            assert_eq!(message_octets, encoded_octets);
        }
        PaddingOutcome::NotRequested => {}
    }
}

fn compression_boundary_query(udp_payload_size: u16) -> Message {
    let edge = DomainName::from_labels(vec![b"edge".to_vec()]).unwrap();
    Message::builder()
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([
            Edns::new(udp_payload_size).into_record(),
            crate::ResourceRecord {
                name: DomainName::root(),
                rtype: RecordType::NULL,
                class: ClassType::IN,
                ttl: 0,
                rdata: crate::RData::NULL(vec![0; 16_343]),
            },
            crate::ResourceRecord {
                name: edge.clone(),
                rtype: RecordType::NULL,
                class: ClassType::IN,
                ttl: 0,
                rdata: crate::RData::NULL(Vec::new()),
            },
            crate::ResourceRecord {
                name: edge,
                rtype: RecordType::Unknown(65_000),
                class: ClassType::IN,
                ttl: 0,
                rdata: crate::RData::Unknown(Vec::new()),
            },
        ])
        .build()
        .unwrap()
}

mod queries;
mod request_options;
mod responses_and_boundaries;

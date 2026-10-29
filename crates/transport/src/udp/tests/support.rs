use super::*;

pub(super) fn oversized_response() -> Message {
    let name = DomainName::from_labels(vec![b"example".to_vec()]).unwrap();
    let record = |owner: &[u8]| ResourceRecord {
        name: DomainName::from_labels(vec![owner.to_vec(), b"example".to_vec()]).unwrap(),
        rtype: RecordType::NULL,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NULL(vec![0; 220]),
    };
    Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: name,
            qtype: QueryType::ANY,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .answers([record(b"answer")])
        .authorities([record(b"authority")])
        .additionals([record(b"additional")])
        .build()
        .unwrap()
}

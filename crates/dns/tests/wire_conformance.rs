//! Independent wire fixtures for RFC 1035 §§3.3/4.1, RFC 3597 §4,
//! RFC 4034 §§3.1.7/4.1.1, RFC 2782, and RFC 6891 §6.1.3.
//!
//! Build bytes directly so an encoder bug cannot manufacture the oracle.

use dns::{DomainName, FromWire, IntoWire, Message, RData, RecordType};

const ROOT_A_QUESTION: &[u8] = &[0, 0, 1, 0, 1];
const EXAMPLE_QUESTION: &[u8] = b"\x07example\0\0\x01\0\x01";
const QUESTION_POINTER: &[u8] = &[0xc0, 12];

fn packet(counts: [u16; 4], body: &[u8]) -> Vec<u8> {
    let mut wire: Vec<_> = [0x1234, 0x8000]
        .into_iter()
        .chain(counts)
        .flat_map(u16::to_be_bytes)
        .collect();
    wire.extend_from_slice(body);
    wire
}

fn record(owner: &[u8], kind: RecordType, data: &[u8]) -> Vec<u8> {
    let mut wire = owner.to_vec();
    wire.extend_from_slice(&u16::from(kind).to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&60_u32.to_be_bytes());
    wire.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(data);
    wire
}

fn answer(kind: RecordType, data: &[u8]) -> Vec<u8> {
    packet([0, 1, 0, 0], &record(&[0], kind, data))
}

fn assert_rejected(wire: &[u8]) {
    let result = std::panic::catch_unwind(|| Message::from_wire(wire));
    assert!(result.is_ok(), "decoder panicked for {wire:02x?}");
    assert!(result.unwrap().is_err(), "accepted {wire:02x?}");
}

#[test]
fn every_octet_value_is_legal_inside_a_label() {
    for start in (0..=255).step_by(63) {
        let payload: Vec<_> = (start..=(start + 62).min(255)).map(|n| n as u8).collect();
        let mut question = vec![payload.len() as u8];
        question.extend_from_slice(&payload);
        question.extend_from_slice(ROOT_A_QUESTION);
        let message = Message::from_wire(&packet([1, 0, 0, 0], &question)).unwrap();
        assert_eq!(message.questions[0].qname.as_ref(), &[payload]);
    }
}

#[test]
fn root_any_type_and_class_question_has_no_implicit_label() {
    let message = Message::from_wire(&packet([1, 0, 0, 0], &[0, 0, 255, 0, 255])).unwrap();
    assert_eq!(message.questions[0].qname, DomainName::root());
    assert_eq!(message.questions[0].qtype, dns::QueryType::ANY);
    assert_eq!(message.questions[0].qclass, dns::QClassType::ANY);
}

#[test]
fn every_truncation_of_a_valid_multi_section_message_is_rejected() {
    let mut body = EXAMPLE_QUESTION.to_vec();
    body.extend(record(QUESTION_POINTER, RecordType::A, &[192, 0, 2, 1]));
    body.extend(record(QUESTION_POINTER, RecordType::NS, b"\x02ns\xc0\x0c"));
    body.extend(record(b"\x02ns\xc0\x0c", RecordType::AAAA, &[0x20; 16]));
    let wire = packet([1, 1, 1, 1], &body);
    assert!(Message::from_wire(&wire).is_ok());
    for end in 0..wire.len() {
        assert_rejected(&wire[..end]);
    }
}

#[test]
fn address_rdata_requires_exact_ipv4_and_ipv6_widths() {
    for (kind, width) in [(RecordType::A, 4), (RecordType::AAAA, 16)] {
        assert!(Message::from_wire(&answer(kind, &vec![0; width])).is_ok());
        for length in 0..=width + 2 {
            if length != width {
                assert_rejected(&answer(kind, &vec![0; length]));
            }
        }
    }
}

#[test]
fn empty_txt_string_is_distinct_from_absent_txt_strings() {
    let message = Message::from_wire(&answer(RecordType::TXT, &[0])).unwrap();
    assert!(matches!(&message.answers[0].rdata, RData::TXT(strings)
        if strings == &[Vec::<u8>::new()]));
    assert_rejected(&answer(RecordType::TXT, &[]));
}

#[test]
fn txt_strings_preserve_binary_data_and_maximum_character_string_length() {
    let mut data = vec![255];
    data.extend(0..=254);
    data.extend_from_slice(&[0, 1, 0xff]);
    let message = Message::from_wire(&answer(RecordType::TXT, &data)).unwrap();
    assert!(matches!(&message.answers[0].rdata, RData::TXT(strings)
        if strings == &[(0..=254).collect::<Vec<_>>(), vec![], vec![255]]));
}

#[test]
fn txt_character_string_length_cannot_cross_rdlength() {
    for data in [&[1][..], &[2, b'a'][..], &[255, 0][..]] {
        assert_rejected(&answer(RecordType::TXT, data));
    }
}

#[test]
fn hinfo_requires_exactly_two_complete_character_strings() {
    assert!(Message::from_wire(&answer(RecordType::HINFO, &[0, 0])).is_ok());
    for data in [&[][..], &[0][..], &[0, 1][..], &[0, 0, 0][..]] {
        assert_rejected(&answer(RecordType::HINFO, data));
    }
}

#[test]
fn mx_requires_a_preference_and_a_complete_exchange_name() {
    assert!(Message::from_wire(&answer(RecordType::MX, &[0, 10, 0])).is_ok());
    for data in [&[][..], &[0][..], &[0, 10][..], &[0, 10, 1][..]] {
        assert_rejected(&answer(RecordType::MX, data));
    }
}

#[test]
fn soa_requires_two_names_and_five_full_unsigned_words() {
    let mut data = vec![0, 0];
    for word in [u32::MAX, 0x8000_0000, 1, 2, 3] {
        data.extend_from_slice(&word.to_be_bytes());
    }
    assert!(Message::from_wire(&answer(RecordType::SOA, &data)).is_ok());
    for end in 0..data.len() {
        assert_rejected(&answer(RecordType::SOA, &data[..end]));
    }
}

#[test]
fn rdata_cannot_borrow_missing_octets_from_the_next_record() {
    let mut body = record(&[0], RecordType::A, &[192, 0, 2]);
    body.extend(record(&[0], RecordType::AAAA, &[0; 16]));
    assert_rejected(&packet([0, 2, 0, 0], &body));
}

#[test]
fn rdata_cannot_hide_trailing_octets_before_the_next_record() {
    let mut body = record(&[0], RecordType::A, &[192, 0, 2, 1, 0]);
    body.extend(record(&[0], RecordType::AAAA, &[0; 16]));
    assert_rejected(&packet([0, 2, 0, 0], &body));
}

#[test]
fn untrusted_maximum_section_counts_require_actual_records() {
    for section in 0..4 {
        let mut counts = [0; 4];
        counts[section] = u16::MAX;
        assert_rejected(&packet(counts, &[]));
    }
}

#[test]
fn pointers_into_name_shaped_opaque_rdata_are_invalid() {
    let mut body = EXAMPLE_QUESTION.to_vec();
    let opaque_start = 12 + body.len() + 12; // compressed owner + fixed RR header
    body.extend(record(
        QUESTION_POINTER,
        RecordType::Unknown(65000),
        b"\x03www\0",
    ));
    body.extend(record(
        &(0xc000 | opaque_start as u16).to_be_bytes(),
        RecordType::A,
        &[192, 0, 2, 1],
    ));
    assert_rejected(&packet([1, 2, 0, 0], &body));
}

#[test]
fn pointers_can_reference_a_previously_decoded_rdata_name() {
    let mut body = EXAMPLE_QUESTION.to_vec();
    let target = 12 + body.len() + 12;
    body.extend(record(QUESTION_POINTER, RecordType::NS, b"\x02ns\xc0\x0c"));
    body.extend(record(
        &(0xc000 | target as u16).to_be_bytes(),
        RecordType::A,
        &[192, 0, 2, 1],
    ));
    let message = Message::from_wire(&packet([1, 2, 0, 0], &body)).unwrap();
    assert_eq!(
        message.answers[1].name,
        DomainName::from_dotted("ns.example").unwrap()
    );
}

#[test]
fn unknown_rdata_preserves_even_impossible_compression_pointer_bytes() {
    let data = [0xff, 0xff, 0xc0, 0, 0x40, 0];
    let wire = answer(RecordType::Unknown(65000), &data);
    let message = Message::from_wire(&wire).unwrap();
    assert!(matches!(&message.answers[0].rdata, RData::Unknown(bytes) if bytes == &data));
    assert_eq!(message.into_wire().unwrap(), wire);
}

#[test]
fn prohibited_rdata_name_compression_is_rejected_even_with_a_valid_target() {
    // Prefix/suffix bytes are identical in each pair; only the name uses
    // a pointer. Positive controls exclude rejection for unrelated RDATA.
    for (kind, prefix, suffix) in [
        (RecordType::DNAME, 0, vec![]),
        (RecordType::SRV, 6, vec![]),
        (RecordType::SIG, 18, vec![1]),
        (RecordType::RRSIG, 18, vec![1]),
        (RecordType::NSEC, 0, vec![0, 1, 0x40]), // bitmap containing A
        (RecordType::TSIG, 0, vec![0; 16]),
    ] {
        let message = |target: &[u8]| {
            let mut data = vec![0; prefix];
            data.extend_from_slice(target);
            data.extend_from_slice(&suffix);
            let mut rr = record(QUESTION_POINTER, kind, &data);
            let counts = if kind == RecordType::TSIG {
                // RFC 8945 requires additional-section TSIG, CLASS ANY, TTL 0.
                rr[4..6].copy_from_slice(&255_u16.to_be_bytes());
                rr[6..10].copy_from_slice(&0_u32.to_be_bytes());
                [1, 0, 0, 1]
            } else {
                [1, 1, 0, 0]
            };
            let mut body = EXAMPLE_QUESTION.to_vec();
            body.extend(rr);
            packet(counts, &body)
        };
        assert!(
            Message::from_wire(&message(b"\x07example\0")).is_ok(),
            "invalid positive control for {kind:?}"
        );
        assert!(
            matches!(
                Message::from_wire(&message(QUESTION_POINTER)),
                Err(dns::wire::WireError::InvalidRData { detail, .. })
                    if detail.contains("must not use compression")
            ),
            "wrong rejection for {kind:?}"
        );
    }
}

#[test]
fn opt_metadata_does_not_undergo_ordinary_ttl_normalization() {
    let mut body = record(&[0], RecordType::OPT, &[]);
    body[3..5].copy_from_slice(&4096_u16.to_be_bytes());
    body[5..9].copy_from_slice(&0xff00_8000_u32.to_be_bytes());
    let message = Message::from_wire(&packet([0, 0, 0, 1], &body)).unwrap();
    let edns = message.edns().unwrap().unwrap();
    assert_eq!(edns.extended_rcode, 255);
    assert!(edns.dnssec_ok);
    assert_eq!(edns.udp_payload_size, 4096);
}

#[test]
fn every_single_octet_mutation_and_prefix_decodes_without_panicking() {
    let mut body = EXAMPLE_QUESTION.to_vec();
    body.extend(record(QUESTION_POINTER, RecordType::A, &[192, 0, 2, 1]));
    body.extend(record(
        QUESTION_POINTER,
        RecordType::TXT,
        &[3, 0xff, 0, 0xc0],
    ));
    let original = packet([1, 2, 0, 0], &body);
    let mut mutated = original.clone();
    for index in 0..original.len() {
        for value in 0..=u8::MAX {
            mutated[index] = value;
            assert!(
                std::panic::catch_unwind(|| Message::from_wire(&mutated)).is_ok(),
                "panic at octet {index}, value {value}"
            );
        }
        mutated[index] = original[index];
    }
    for end in 0..original.len() {
        assert_rejected(&original[..end]);
    }
    assert!(Message::from_wire(&original).is_ok());
}

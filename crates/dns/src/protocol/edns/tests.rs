use crate::{FromWire, Headers, IntoWire, MessageValidationError, RCode, RecordValidationError};

use super::*;

#[test]
fn opt_fixed_fields_and_unknown_options_round_trip() {
    let edns = Edns {
        udp_payload_size: 4096,
        extended_rcode: 1,
        version: 0,
        dnssec_ok: true,
        z: 0,
        options: vec![
            EdnsOption {
                code: 65_001,
                data: vec![0xaa, 0xbb, 0xcc],
            },
            EdnsOption {
                code: 65_002,
                data: Vec::new(),
            },
        ],
    };
    let wire = edns.clone().into_record().into_wire().unwrap();
    assert_eq!(
        wire,
        [
            0x00, 0x00, 0x29, 0x10, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x0b, 0xfd, 0xe9, 0x00,
            0x03, 0xaa, 0xbb, 0xcc, 0xfd, 0xea, 0x00, 0x00,
        ]
    );
    let record = ResourceRecord::from_wire(&wire).unwrap();
    assert_eq!(Edns::try_from_record(&record).unwrap(), edns);
}

#[test]
fn payload_sizes_below_512_have_an_effective_512_byte_limit() {
    for size in [0, 1, 511] {
        assert_eq!(Edns::new(size).effective_udp_payload_size(), 512);
    }
    assert_eq!(Edns::new(513).effective_udp_payload_size(), 513);
}

#[test]
fn rfc6975_algorithm_signals_round_trip_and_union_in_order() {
    let mut edns = Edns::new(1_232);
    edns.set_algorithm_signal(DnssecAlgorithmSignal::Dau, [8, 13, 15, 8])
        .unwrap();
    edns.set_algorithm_signal(DnssecAlgorithmSignal::Dhu, [2])
        .unwrap();
    edns.set_algorithm_signal(DnssecAlgorithmSignal::N3u, [1])
        .unwrap();
    edns.union_algorithm_signal(DnssecAlgorithmSignal::Dau, [15, 10])
        .unwrap();

    assert!(edns.dnssec_ok);
    assert_eq!(
        edns.algorithm_signal(DnssecAlgorithmSignal::Dau).unwrap(),
        Some([8, 13, 15, 10].as_slice())
    );
    assert_eq!(
        edns.algorithm_signal(DnssecAlgorithmSignal::Dhu).unwrap(),
        Some([2].as_slice())
    );
    assert_eq!(
        edns.algorithm_signal(DnssecAlgorithmSignal::N3u).unwrap(),
        Some([1].as_slice())
    );

    let wire = edns.clone().into_record().into_wire().unwrap();
    let decoded = Edns::try_from_record(&ResourceRecord::from_wire(&wire).unwrap()).unwrap();
    assert_eq!(decoded, edns);
    let mut response = decoded;
    response.remove_algorithm_signals();
    assert!(response.options.is_empty());
}

#[test]
fn rfc6975_rejects_duplicate_options_and_reserved_sender_codes() {
    let mut edns = Edns::default();
    assert!(matches!(
        edns.set_algorithm_signal(DnssecAlgorithmSignal::Dau, [0]),
        Err(DnssecAlgorithmSignalError::ReservedAlgorithm {
            option_code: 5,
            algorithm: 0
        })
    ));
    assert!(matches!(
        edns.set_algorithm_signal(DnssecAlgorithmSignal::Dhu, [u8::MAX]),
        Err(DnssecAlgorithmSignalError::ReservedAlgorithm {
            option_code: 6,
            algorithm: 255
        })
    ));

    edns.options = vec![
        EdnsOption {
            code: 5,
            data: vec![8],
        },
        EdnsOption {
            code: 5,
            data: vec![10],
        },
    ];
    assert!(matches!(
        edns.algorithm_signal(DnssecAlgorithmSignal::Dau),
        Err(DnssecAlgorithmSignalError::DuplicateOption { code: 5 })
    ));
    assert!(matches!(
        edns.validate_options(),
        Err(RecordValidationError::DuplicateDnssecAlgorithmSignal { code: 5 })
    ));

    // Local construction rejects reserved values; forwarding preserves the
    // received advisory bytes.
    edns.options = vec![EdnsOption {
        code: 7,
        data: vec![0],
    }];
    assert!(edns.validate_options().is_ok());
    let record = edns.into_record();
    assert!(
        Message::builder()
            .additionals([record.clone()])
            .build()
            .is_err()
    );
    assert_eq!(
        ResourceRecord::from_wire(&record.into_wire().unwrap())
            .unwrap()
            .rdata,
        record.rdata
    );
}

#[test]
fn a_message_exposes_the_full_twelve_bit_response_code() {
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            rcode: RCode::Refused,
            ..Headers::default()
        })
        .additionals([Edns {
            extended_rcode: 0xab,
            ..Edns::default()
        }
        .into_record()])
        .build()
        .unwrap();

    assert_eq!(message.extended_rcode(), 0xab5);
    assert_eq!(
        Message::from_wire(&message.into_wire().unwrap())
            .unwrap()
            .extended_rcode(),
        0xab5
    );
}

#[test]
fn outbound_validation_enforces_opt_placement_cardinality_and_request_rcode() {
    let opt = Edns::default().into_record();
    assert!(matches!(
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .answers([opt.clone()])
            .build(),
        Err(MessageValidationError::OptOutsideAdditional)
    ));
    assert!(matches!(
        Message::builder()
            .additionals([opt.clone(), opt.clone()])
            .build(),
        Err(MessageValidationError::MultipleOpt)
    ));
    assert!(matches!(
        Message::builder()
            .additionals([Edns {
                extended_rcode: 1,
                ..Edns::default()
            }
            .into_record()])
            .build(),
        Err(MessageValidationError::ExtendedRcodeInRequest)
    ));
}

#[test]
fn non_root_opt_is_rejected_by_edns_and_message_validation() {
    let mut opt = Edns::default().into_record();
    opt.name = DomainName::from_labels(vec![b"example".to_vec()]).unwrap();

    assert_eq!(
        Edns::try_from_record(&opt),
        Err(EdnsRecordError::NonRootName)
    );
    assert!(matches!(
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .additionals([opt])
            .build(),
        Err(MessageValidationError::InvalidRecord {
            section: "additional",
            index: 0,
            error: RecordValidationError::InvalidRDataType,
        })
    ));
}

#[test]
fn decoder_preserves_nonzero_z_and_option_validation_ignores_it() {
    let wire = [
        0, 0, 41, 2, 0, // NAME, TYPE, payload 512
        0, 0, 0, 1, // TTL with Z bit 0 set
        0, 6, // RDLENGTH
        0, 15, 0, 2, 0, 0, // valid EDE Other option
    ];
    let record = ResourceRecord::from_wire(&wire).unwrap();
    let edns = Edns::try_from_record(&record).unwrap();
    assert_eq!(edns.z, 1);
    assert!(edns.validate_options().is_ok());
    assert!(record.into_wire().is_err());
}

#[test]
fn malformed_option_lengths_are_rejected() {
    let wire = [
        0, 0, 41, 2, 0, // NAME, TYPE, payload 512
        0, 0, 0, 0, // TTL
        0, 5, // RDLENGTH
        0, 15, 0, 2, 0xaa, // claims two data octets, supplies one
    ];
    assert!(ResourceRecord::from_wire(&wire).is_err());
}

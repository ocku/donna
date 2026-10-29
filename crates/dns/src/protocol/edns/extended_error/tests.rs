use crate::{FromWire, IntoWire, Message, RData, RecordValidationError};

use super::*;

#[test]
fn all_rfc8914_codes_and_unknown_values_round_trip() {
    for value in 0..=u16::MAX {
        let code = ExtendedDnsErrorCode::from(value);
        assert_eq!(code.value(), value);
        assert_eq!(u16::from(code), value);
        assert_eq!(code.is_private_use(), value >= 49_152);
    }
}

#[test]
fn unicode_and_null_terminated_text_round_trip_on_the_wire() {
    let ede = ExtendedDnsError::new(
        ExtendedDnsErrorCode::DnssecBogus,
        "signatur ogiltig – kontrollera nyckeln\0",
    )
    .unwrap();
    let mut edns = Edns::new(1232);
    edns.push_extended_dns_error(ede.clone()).unwrap();
    let message = Message::builder()
        .additionals([edns.into_record()])
        .build()
        .unwrap();

    let wire = message.into_wire().unwrap();
    assert!(wire.windows(4).any(|window| window == [0, 15, 0, 43]));
    let decoded = Message::from_wire(&wire).unwrap().edns().unwrap().unwrap();
    assert_eq!(
        decoded.extended_dns_errors().collect::<Result<Vec<_>, _>>(),
        Ok(vec![ede])
    );
}

#[test]
fn outbound_extra_text_is_normalized_to_nfc() {
    let cases = [
        ("Cafe\u{301}", "Caf\u{e9}"),
        ("\u{1100}\u{1161}", "\u{ac00}"),
        ("a\u{315}\u{300}", "\u{e0}\u{315}"),
    ];

    for (decomposed, composed) in cases {
        let constructed = ExtendedDnsError::new(ExtendedDnsErrorCode::Other, decomposed).unwrap();
        assert_eq!(constructed.extra_text, composed);

        let directly_constructed = ExtendedDnsError {
            info_code: ExtendedDnsErrorCode::Other,
            extra_text: decomposed.to_owned(),
        };
        let option = directly_constructed.into_option().unwrap();
        assert_eq!(&option.data[2..], composed.as_bytes());
        assert_eq!(
            ExtendedDnsError::try_from_option(&option)
                .unwrap()
                .extra_text,
            composed
        );
    }
}

#[test]
fn inbound_valid_utf8_is_accepted_and_normalized_to_nfc() {
    let composed = EdnsOption {
        code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
        data: [vec![0, 0], "Caf\u{e9}".as_bytes().to_vec()].concat(),
    };
    assert!(ExtendedDnsError::try_from_option(&composed).is_ok());

    let decomposed = EdnsOption {
        code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
        data: [vec![0, 0], "Cafe\u{301}".as_bytes().to_vec()].concat(),
    };
    assert_eq!(
        ExtendedDnsError::try_from_option(&decomposed)
            .unwrap()
            .extra_text,
        "Caf\u{e9}"
    );
    assert_eq!(
        Edns {
            options: vec![decomposed],
            ..Edns::default()
        }
        .validate_options(),
        Ok(())
    );
}

fn assert_outbound_extra_text_rejected(extra_text: &str, expected: ExtendedDnsErrorError) {
    assert_eq!(
        ExtendedDnsError::new(ExtendedDnsErrorCode::Other, extra_text),
        Err(expected)
    );
    assert_eq!(
        ExtendedDnsError {
            info_code: ExtendedDnsErrorCode::Other,
            extra_text: extra_text.to_owned(),
        }
        .into_option(),
        Err(expected)
    );
}

#[test]
fn outbound_extra_text_rejects_every_c1_control() {
    for code_point in 0x80..=0x9f {
        let character = char::from_u32(code_point).unwrap();
        assert_outbound_extra_text_rejected(
            &format!("before{character}after"),
            ExtendedDnsErrorError::ExtraTextContainsC1Control { code_point },
        );
    }
}

#[test]
fn outbound_extra_text_rejects_only_an_initial_bom_signature() {
    assert_outbound_extra_text_rejected(
        "\u{feff}diagnostic",
        ExtendedDnsErrorError::ExtraTextStartsWithBom,
    );

    let internal =
        ExtendedDnsError::new(ExtendedDnsErrorCode::Other, "diagnostic \u{feff} marker").unwrap();
    assert_eq!(internal.extra_text, "diagnostic \u{feff} marker");
}

#[test]
fn outbound_extra_text_rejects_unassigned_but_allows_private_use() {
    for character in ['\u{378}', '\u{379}', '\u{fdd0}', '\u{10ffff}'] {
        assert!(!is_public_assigned(character));
        assert_outbound_extra_text_rejected(
            &character.to_string(),
            ExtendedDnsErrorError::ExtraTextContainsUnassignedCodePoint {
                code_point: u32::from(character),
            },
        );
    }

    // RFC 5198 recommends avoiding private-use characters but does not
    // prohibit them, so all three private-use areas remain representable.
    for character in [
        '\u{e000}',
        '\u{f8ff}',
        '\u{f0000}',
        '\u{ffffd}',
        '\u{100000}',
        '\u{10fffd}',
    ] {
        assert!(ExtendedDnsError::new(ExtendedDnsErrorCode::Other, character.to_string()).is_ok());
    }
}

#[test]
fn outbound_extra_text_enforces_net_unicode_carriage_returns() {
    for (text, byte_index) in [("\r", 0), ("\rx", 0), ("prefix\rsuffix", 6)] {
        assert_outbound_extra_text_rejected(
            text,
            ExtendedDnsErrorError::ExtraTextContainsInvalidCarriageReturn { byte_index },
        );
    }

    for text in ["line one\r\nline two", "overstrike\r\0text", "bare\nlf"] {
        assert!(ExtendedDnsError::new(ExtendedDnsErrorCode::Other, text).is_ok());
    }
}

#[test]
fn outbound_extra_text_rejects_unicode_line_separators() {
    for character in ['\u{2028}', '\u{2029}'] {
        assert_outbound_extra_text_rejected(
            &format!("first{character}second"),
            ExtendedDnsErrorError::ExtraTextContainsUnicodeLineSeparator {
                code_point: u32::from(character),
            },
        );
    }
}

#[test]
fn received_extra_text_remains_tolerant_of_sender_profile_violations() {
    for text in [
        "\u{feff}leading BOM",
        "C1 \u{80}",
        "unassigned \u{378}",
        "bare\rcarriage return",
        "line\u{2028}separator",
        "Cafe\u{301}",
    ] {
        let option = EdnsOption {
            code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
            data: [vec![0, 0], text.as_bytes().to_vec()].concat(),
        };
        let decoded = ExtendedDnsError::try_from_option(&option).unwrap();
        assert_eq!(decoded.extra_text, text.nfc().collect::<String>());
        assert_eq!(
            Edns {
                options: vec![option],
                ..Edns::default()
            }
            .validate_options(),
            Ok(())
        );
    }
}

#[test]
fn raw_outbound_ede_options_cannot_bypass_the_sender_profile() {
    for text in ["\u{feff}", "\u{80}", "\u{378}", "\r", "\u{2028}"] {
        let record = Edns {
            options: vec![EdnsOption {
                code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
                data: [vec![0, 0], text.as_bytes().to_vec()].concat(),
            }],
            ..Edns::default()
        }
        .into_record();
        assert_eq!(
            record.validate(),
            Err(RecordValidationError::ExtendedDnsErrorTextNotNetUnicode)
        );
        assert!(matches!(record.rdata, RData::OPT(_)));
    }
}

#[test]
fn zero_length_text_and_unknown_codes_are_preserved() {
    let ede = ExtendedDnsError::without_text(ExtendedDnsErrorCode::Unknown(65_000));
    let option = ede.clone().into_option().unwrap();
    assert_eq!(option.data, [0xfd, 0xe8]);
    assert_eq!(ExtendedDnsError::try_from_option(&option), Ok(ede));
}

#[test]
fn multiple_errors_are_accepted_in_order() {
    let mut edns = Edns::default();
    edns.push_extended_dns_error(ExtendedDnsError::without_text(
        ExtendedDnsErrorCode::StaleAnswer,
    ))
    .unwrap();
    edns.options.push(EdnsOption {
        code: 65_000,
        data: vec![1],
    });
    edns.push_extended_dns_error(
        ExtendedDnsError::new(ExtendedDnsErrorCode::NetworkError, "timeout").unwrap(),
    )
    .unwrap();

    let errors = edns
        .extended_dns_errors()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].info_code, ExtendedDnsErrorCode::StaleAnswer);
    assert_eq!(errors[1].info_code, ExtendedDnsErrorCode::NetworkError);
    assert!(edns.remove_extended_dns_errors());
    assert_eq!(edns.options.len(), 1);
    assert!(!edns.remove_extended_dns_errors());
}

#[test]
fn malformed_payloads_report_the_exact_format_problem() {
    for data in [vec![], vec![0]] {
        assert!(matches!(
            ExtendedDnsError::try_from_option(&EdnsOption {
                code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
                data: data.clone(),
            }),
            Err(ExtendedDnsErrorError::MissingInfoCode { length }) if length == data.len()
        ));
    }
    assert_eq!(
        ExtendedDnsError::try_from_option(&EdnsOption {
            code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
            data: vec![0, 1, 0xff],
        }),
        Err(ExtendedDnsErrorError::ExtraTextNotUtf8)
    );
    assert!(matches!(
        ExtendedDnsError::try_from_option(&EdnsOption {
            code: 12,
            data: vec![0, 1],
        }),
        Err(ExtendedDnsErrorError::WrongOptionCode { code: 12 })
    ));
}

#[test]
fn constructor_enforces_the_option_length_limit() {
    assert!(
        ExtendedDnsError::new(
            ExtendedDnsErrorCode::Other,
            "x".repeat(ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS)
        )
        .is_ok()
    );
    assert!(matches!(
        ExtendedDnsError::new(
            ExtendedDnsErrorCode::Other,
            "x".repeat(ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS + 1)
        ),
        Err(ExtendedDnsErrorError::ExtraTextTooLong { .. })
    ));
}

#[test]
fn option_length_limit_is_checked_after_normalization() {
    // This input is one octet too long before normalization, but its final
    // e + combining acute pair composes to a two-octet code point.
    let becomes_exactly_maximum = format!(
        "{}e\u{301}",
        "x".repeat(ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS - 2)
    );
    assert_eq!(
        becomes_exactly_maximum.len(),
        ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS + 1
    );
    let error =
        ExtendedDnsError::new(ExtendedDnsErrorCode::Other, becomes_exactly_maximum).unwrap();
    assert_eq!(
        error.extra_text.len(),
        ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS
    );
    assert_eq!(
        error.into_option().unwrap().data.len(),
        usize::from(u16::MAX)
    );

    // U+0344 canonically decomposes under NFC, so normalization can also
    // make an initially representable string exceed OPTION-LENGTH.
    let expands_past_maximum = format!(
        "{}\u{344}",
        "x".repeat(ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS - 2)
    );
    assert_eq!(
        expands_past_maximum.len(),
        ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS
    );
    assert_eq!(
        ExtendedDnsError::new(ExtendedDnsErrorCode::Other, expands_past_maximum.clone()),
        Err(ExtendedDnsErrorError::ExtraTextTooLong {
            length: ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS + 2,
        })
    );
    assert_eq!(
        ExtendedDnsError {
            info_code: ExtendedDnsErrorCode::Other,
            extra_text: expands_past_maximum,
        }
        .into_option(),
        Err(ExtendedDnsErrorError::ExtraTextTooLong {
            length: ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS + 2,
        })
    );
}

#[test]
fn outbound_unknown_rejects_known_codes_but_preserves_future_and_private_codes() {
    for value in 0..=24 {
        let error = ExtendedDnsError::without_text(ExtendedDnsErrorCode::Unknown(value));
        assert_eq!(
            error.into_option(),
            Err(ExtendedDnsErrorError::NonCanonicalInfoCode { value })
        );
    }

    for value in [25, 49_151, 49_152, u16::MAX] {
        let error = ExtendedDnsError::without_text(ExtendedDnsErrorCode::Unknown(value));
        let option = error.clone().into_option().unwrap();
        assert_eq!(ExtendedDnsError::try_from_option(&option), Ok(error));
    }
}

#[test]
fn public_field_construction_cannot_bypass_option_length_validation() {
    let error = ExtendedDnsError {
        info_code: ExtendedDnsErrorCode::Other,
        extra_text: "x".repeat(ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS + 1),
    };
    assert!(matches!(
        error.into_option(),
        Err(ExtendedDnsErrorError::ExtraTextTooLong { .. })
    ));
}

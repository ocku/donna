use super::*;

#[test]
fn duplicate_request_padding_is_rejected_without_modifying_response() {
    let mut request = query();
    set_edns_options(
        &mut request,
        vec![EdnsOption::padding(0), EdnsOption::padding(1)],
    );
    let mut response = response();
    let before = response.into_wire().unwrap();

    let error = response
        .pad_response_for_encrypted_transport(&request, 1404)
        .unwrap_err();
    assert_eq!(
        error,
        PaddingPolicyError::InvalidEdnsOptions(RecordValidationError::DuplicateEdnsPadding)
    );
    assert_eq!(
        error.to_string(),
        concat!(
            "cannot apply padding with invalid EDNS options: ",
            "an OPT record may contain only one EDNS Padding option",
        )
    );
    assert_eq!(
        <PaddingPolicyError as std::error::Error>::source(&error)
            .and_then(|source| source.downcast_ref::<RecordValidationError>()),
        Some(&RecordValidationError::DuplicateEdnsPadding)
    );
    assert_eq!(response.into_wire().unwrap(), before);
}

#[test]
fn malformed_ede_with_padding_is_rejected_before_response_padding() {
    let mut request = query();
    set_edns_options(
        &mut request,
        vec![
            EdnsOption {
                code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
                data: vec![0],
            },
            EdnsOption::padding(0),
        ],
    );
    let mut response = response();
    let before = response.into_wire().unwrap();

    assert_eq!(
        response.pad_response_for_encrypted_transport(&request, 0),
        Err(PaddingPolicyError::InvalidEdnsOptions(
            RecordValidationError::ExtendedDnsErrorMissingInfoCode { length: 1 }
        ))
    );
    assert_eq!(response.into_wire().unwrap(), before);
}

#[test]
fn malformed_ede_without_padding_is_rejected_instead_of_not_requested() {
    let mut request = query();
    set_edns_options(
        &mut request,
        vec![EdnsOption {
            code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
            data: vec![0],
        }],
    );
    let mut response = response();
    let before = response.into_wire().unwrap();

    assert_eq!(
        response.pad_response_for_encrypted_transport(&request, 1404),
        Err(PaddingPolicyError::InvalidEdnsOptions(
            RecordValidationError::ExtendedDnsErrorMissingInfoCode { length: 1 }
        ))
    );
    assert_eq!(response.into_wire().unwrap(), before);
}

#[test]
fn valid_nonfinal_singleton_request_padding_is_accepted() {
    let mut request = query();
    set_edns_options(
        &mut request,
        vec![
            EdnsOption {
                code: EDNS_PADDING_OPTION_CODE,
                data: vec![0xff, 0x01],
            },
            EdnsOption {
                code: 65_000,
                data: vec![1],
            },
        ],
    );
    let mut response = response();

    assert!(matches!(
        response.pad_response_for_encrypted_transport(&request, 1404),
        Ok(PaddingOutcome::Padded {
            message_octets: 468,
            block_aligned: true,
            ..
        })
    ));
}

#[test]
fn unknown_request_options_do_not_prevent_response_padding() {
    let mut request = query();
    set_edns_options(
        &mut request,
        vec![
            EdnsOption {
                code: 65_000,
                data: vec![0xff, 0x00, 0x80],
            },
            EdnsOption::padding(0),
        ],
    );
    let mut response = response();

    assert!(matches!(
        response.pad_response_for_encrypted_transport(&request, 1404),
        Ok(PaddingOutcome::Padded {
            message_octets: 468,
            block_aligned: true,
            ..
        })
    ));
}

#[test]
fn malformed_response_options_use_the_specific_error_transactionally() {
    let mut request = query();
    set_edns_options(&mut request, vec![EdnsOption::padding(0)]);
    let mut response = response();
    set_edns_options(
        &mut response,
        vec![EdnsOption {
            code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
            data: vec![0],
        }],
    );
    let before = response.edns().unwrap().unwrap();

    assert_eq!(
        response.pad_response_for_encrypted_transport(&request, 1404),
        Err(PaddingPolicyError::InvalidEdnsOptions(
            RecordValidationError::ExtendedDnsErrorMissingInfoCode { length: 1 }
        ))
    );
    assert_eq!(response.edns().unwrap().unwrap(), before);
}

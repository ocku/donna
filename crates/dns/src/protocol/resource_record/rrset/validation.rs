#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

use crate::constants::character_string::MAX_OCTETS as MAX_CHARACTER_STRING_OCTETS;
use crate::{
    ClassType, EDNS_EXTENDED_DNS_ERROR_OPTION_CODE, EDNS_PADDING_OPTION_CODE, RData, RecordType,
    Tsig,
};
use unicode_normalization::is_nfc;

use super::RecordValidationError;
use crate::protocol::edns::extended_error::validate_outbound_extra_text;
use crate::protocol::is_valid_caa_property_tag;

/// Validates intrinsic RDATA wire limits.
pub(crate) fn validate_rdata_wire(rdata: &RData) -> Result<(), RecordValidationError> {
    validate_rdata_wire_context(rdata, false)
}

pub(crate) fn validate_rdata_forwarded(rdata: &RData) -> Result<(), RecordValidationError> {
    validate_rdata_wire_context(rdata, true)
}

fn validate_rdata_wire_context(
    rdata: &RData,
    forwarded: bool,
) -> Result<(), RecordValidationError> {
    let length = match rdata {
        RData::A(_) => 4,
        RData::AAAA(_) => 16,
        RData::DNAME(name)
        | RData::CNAME(name)
        | RData::NS(name)
        | RData::MD(name)
        | RData::MF(name)
        | RData::MB(name)
        | RData::MG(name)
        | RData::MR(name)
        | RData::PTR(name) => name.wire_len(),
        RData::NULL(bytes) | RData::Unknown(bytes) => bytes.len(),
        RData::WKS { bitmap, .. } => {
            if bitmap.len() > 8192 {
                return Err(RecordValidationError::WksBitmapTooLong {
                    length: bitmap.len(),
                });
            }
            5 + bitmap.len()
        }
        RData::HINFO { cpu, os } => {
            validate_character_string(cpu)?;
            validate_character_string(os)?;
            2 + cpu.len() + os.len()
        }
        RData::MINFO { rmailbx, emailbx } => rmailbx.wire_len() + emailbx.wire_len(),
        RData::MX { exchange, .. } => 2 + exchange.wire_len(),
        RData::SRV { target, .. } => 6 + target.wire_len(),
        RData::TXT(strings) => txt_wire_len(strings)?,

        RData::SIG(sig) => 18 + sig.signer_name.wire_len() + sig.signature.len(),
        RData::KEY(key) => 4 + key.public_key.len(),
        RData::DS(ds) => {
            if let Some(expected) = match ds.digest_type {
                1 => Some(20),
                2 => Some(32),
                _ => None,
            } && ds.digest.len() != expected
            {
                return Err(RecordValidationError::InvalidDsDigestLength {
                    digest_type: ds.digest_type,
                    length: ds.digest.len(),
                    expected,
                });
            }
            4 + ds.digest.len()
        }
        RData::RRSIG(rrsig) => 18 + rrsig.signer_name.wire_len() + rrsig.signature.len(),
        RData::NSEC(nsec) => nsec.next_domain_name.wire_len() + nsec.type_bitmap.wire_len(),
        RData::DNSKEY(dnskey) => 4 + dnskey.public_key.len(),
        RData::NSEC3(nsec3) => nsec3_wire_len(nsec3)?,
        RData::NSEC3PARAM(parameters) => {
            if parameters.salt.len() > usize::from(u8::MAX) {
                return Err(RecordValidationError::Nsec3SaltTooLong {
                    length: parameters.salt.len(),
                });
            }
            5 + parameters.salt.len()
        }
        RData::TLSA(association) | RData::SMIMEA(association) => {
            if association.association_data.is_empty() {
                return Err(RecordValidationError::EmptyCertificateAssociationData);
            }
            if let Some(expected) = association.expected_data_length()
                && association.association_data.len() != expected
            {
                return Err(RecordValidationError::InvalidCertificateAssociationLength {
                    matching_type: association.matching_type,
                    length: association.association_data.len(),
                    expected,
                });
            }
            3 + association.association_data.len()
        }
        RData::OPT(options) => edns_wire_len(options, forwarded)?,
        RData::CAA(caa) => {
            if caa.tag.is_empty() {
                return Err(RecordValidationError::EmptyCaaTag);
            }
            if caa.tag.len() > usize::from(u8::MAX) {
                return Err(RecordValidationError::CaaTagTooLong {
                    length: caa.tag.len(),
                });
            }
            if !is_valid_caa_property_tag(&caa.tag) {
                return Err(RecordValidationError::InvalidCaaTag);
            }
            2 + caa.tag.len() + caa.value.len()
        }
        RData::CSYNC(csync) => 6 + csync.type_bitmap.wire_len(),
        RData::TSIG(tsig) => tsig_wire_len(tsig)?,
        RData::SOA { mname, rname, .. } => mname.wire_len() + rname.wire_len() + 20,
    };

    if length > usize::from(u16::MAX) {
        return Err(RecordValidationError::RDataTooLong { length });
    }
    Ok(())
}

fn nsec3_wire_len(nsec3: &crate::Nsec3) -> Result<usize, RecordValidationError> {
    if nsec3.salt.len() > usize::from(u8::MAX) {
        return Err(RecordValidationError::Nsec3SaltTooLong {
            length: nsec3.salt.len(),
        });
    }
    if nsec3.next_hashed_owner_name.is_empty()
        || nsec3.next_hashed_owner_name.len() > usize::from(u8::MAX)
    {
        return Err(RecordValidationError::InvalidNsec3HashLength {
            length: nsec3.next_hashed_owner_name.len(),
        });
    }
    if nsec3.hash_algorithm == 1 && nsec3.next_hashed_owner_name.len() != 20 {
        return Err(RecordValidationError::InvalidNsec3Sha1HashLength {
            length: nsec3.next_hashed_owner_name.len(),
        });
    }
    Ok(6 + nsec3.salt.len()
        + nsec3.next_hashed_owner_name.len()
        + nsec3
            .type_bitmap
            .as_ref()
            .map_or(0, |bitmap| bitmap.wire_len()))
}

fn edns_wire_len(
    options: &[crate::EdnsOption],
    forwarded: bool,
) -> Result<usize, RecordValidationError> {
    let mut length = 0usize;
    let mut saw_padding = false;
    let mut padding_not_last = false;
    let mut saw_algorithm_signals = [false; 3];
    for (index, option) in options.iter().enumerate() {
        if option.code == EDNS_PADDING_OPTION_CODE {
            if saw_padding {
                return Err(RecordValidationError::DuplicateEdnsPadding);
            }
            saw_padding = true;
            padding_not_last = index + 1 != options.len();
        }
        if let Some(signal_index) = option.code.checked_sub(5).filter(|value| *value < 3) {
            let signal_index = usize::from(signal_index);
            if saw_algorithm_signals[signal_index] {
                return Err(RecordValidationError::DuplicateDnssecAlgorithmSignal {
                    code: option.code,
                });
            }
            saw_algorithm_signals[signal_index] = true;
            if !forwarded
                && let Some(&algorithm) = option
                    .data
                    .iter()
                    .find(|&&algorithm| matches!(algorithm, 0 | u8::MAX))
            {
                return Err(RecordValidationError::ReservedDnssecAlgorithmCode {
                    option_code: option.code,
                    algorithm,
                });
            }
        }
        if option.code == EDNS_EXTENDED_DNS_ERROR_OPTION_CODE {
            if option.data.len() < 2 {
                return Err(RecordValidationError::ExtendedDnsErrorMissingInfoCode {
                    length: option.data.len(),
                });
            }
            let text = std::str::from_utf8(&option.data[2..])
                .map_err(|_| RecordValidationError::ExtendedDnsErrorTextNotUtf8)?;
            if !is_nfc(text) {
                return Err(RecordValidationError::ExtendedDnsErrorTextNotNfc);
            }
            validate_outbound_extra_text(text)
                .map_err(|_| RecordValidationError::ExtendedDnsErrorTextNotNetUnicode)?;
        }
        if option.data.len() > usize::from(u16::MAX) {
            return Err(RecordValidationError::EdnsOptionTooLong {
                length: option.data.len(),
            });
        }
        length = length.saturating_add(4 + option.data.len());
    }
    if padding_not_last {
        return Err(RecordValidationError::EdnsPaddingNotLast);
    }
    Ok(length)
}

fn tsig_wire_len(tsig: &Tsig) -> Result<usize, RecordValidationError> {
    if tsig.time_signed > Tsig::MAX_TIME_SIGNED {
        return Err(RecordValidationError::TsigTimeTooLarge {
            value: tsig.time_signed,
        });
    }
    if tsig.mac.len() > usize::from(u16::MAX) {
        return Err(RecordValidationError::TsigMacTooLong {
            length: tsig.mac.len(),
        });
    }
    if tsig.other_data.len() > usize::from(u16::MAX) {
        return Err(RecordValidationError::TsigOtherDataTooLong {
            length: tsig.other_data.len(),
        });
    }
    Ok(tsig.algorithm.wire_len() + 16 + tsig.mac.len() + tsig.other_data.len())
}

/// Validates EDNS option tuples at a receive boundary.
///
/// RFC 6891 does not assign semantics to option order, so a received singleton
/// Padding option is accepted wherever it occurs. RFC 5198's normalization
/// requirements apply to senders; receivers accept valid UTF-8 EDE text even
/// when it is not already NFC.
pub(crate) fn validate_received_edns_options(
    options: &[crate::EdnsOption],
) -> Result<(), RecordValidationError> {
    let mut length = 0usize;
    let mut saw_padding = false;
    let mut saw_algorithm_signals = [false; 3];

    for option in options {
        if option.code == EDNS_PADDING_OPTION_CODE {
            if saw_padding {
                return Err(RecordValidationError::DuplicateEdnsPadding);
            }
            saw_padding = true;
        }
        if let Some(signal_index) = option.code.checked_sub(5).filter(|value| *value < 3) {
            let signal_index = usize::from(signal_index);
            if saw_algorithm_signals[signal_index] {
                return Err(RecordValidationError::DuplicateDnssecAlgorithmSignal {
                    code: option.code,
                });
            }
            saw_algorithm_signals[signal_index] = true;
        }
        if option.code == EDNS_EXTENDED_DNS_ERROR_OPTION_CODE {
            if option.data.len() < 2 {
                return Err(RecordValidationError::ExtendedDnsErrorMissingInfoCode {
                    length: option.data.len(),
                });
            }
            std::str::from_utf8(&option.data[2..])
                .map_err(|_| RecordValidationError::ExtendedDnsErrorTextNotUtf8)?;
        }
        if option.data.len() > usize::from(u16::MAX) {
            return Err(RecordValidationError::EdnsOptionTooLong {
                length: option.data.len(),
            });
        }
        length = length.saturating_add(4 + option.data.len());
    }

    if length > usize::from(u16::MAX) {
        return Err(RecordValidationError::RDataTooLong { length });
    }
    Ok(())
}

fn validate_character_string(value: &[u8]) -> Result<(), RecordValidationError> {
    if value.len() > MAX_CHARACTER_STRING_OCTETS {
        return Err(RecordValidationError::CharacterStringTooLong {
            length: value.len(),
        });
    }
    Ok(())
}

pub(super) fn rdata_matches_type(rtype: RecordType, class: ClassType, rdata: &RData) -> bool {
    if matches!(
        rtype,
        RecordType::Unknown(code)
            if RecordType::is_known_code(code) || RecordType::is_query_only_code(code)
    ) {
        return false;
    }
    if !rtype.has_standard_rdata_format(class) {
        return matches!(rdata, RData::Unknown(_));
    }

    match rdata {
        RData::A(_) => rtype == RecordType::A,
        RData::AAAA(_) => rtype == RecordType::AAAA,
        RData::NS(_) => rtype == RecordType::NS,
        RData::MD(_) => rtype == RecordType::MD,
        RData::MF(_) => rtype == RecordType::MF,
        RData::CNAME(_) => rtype == RecordType::CNAME,
        RData::DNAME(_) => rtype == RecordType::DNAME,
        RData::SOA { .. } => rtype == RecordType::SOA,
        RData::MB(_) => rtype == RecordType::MB,
        RData::MG(_) => rtype == RecordType::MG,
        RData::MR(_) => rtype == RecordType::MR,
        RData::NULL(_) => rtype == RecordType::NULL,
        RData::WKS { .. } => rtype == RecordType::WKS,
        RData::PTR(_) => rtype == RecordType::PTR,
        RData::HINFO { .. } => rtype == RecordType::HINFO,
        RData::MINFO { .. } => rtype == RecordType::MINFO,
        RData::MX { .. } => rtype == RecordType::MX,
        RData::SRV { .. } => rtype == RecordType::SRV,
        RData::TXT(_) => rtype == RecordType::TXT,
        RData::SIG(_) => rtype == RecordType::SIG,
        RData::KEY(_) => rtype == RecordType::KEY,
        RData::DS(_) => rtype == RecordType::DS,
        RData::RRSIG(_) => rtype == RecordType::RRSIG,
        RData::NSEC(_) => rtype == RecordType::NSEC,
        RData::DNSKEY(_) => rtype == RecordType::DNSKEY,
        RData::NSEC3(_) => rtype == RecordType::NSEC3,
        RData::NSEC3PARAM(_) => rtype == RecordType::NSEC3PARAM,
        RData::TLSA(_) => rtype == RecordType::TLSA,
        RData::SMIMEA(_) => rtype == RecordType::SMIMEA,
        RData::OPT(_) => rtype == RecordType::OPT,
        RData::CAA(_) => rtype == RecordType::CAA,
        RData::CSYNC(_) => rtype == RecordType::CSYNC,
        RData::TSIG(_) => rtype == RecordType::TSIG,
        RData::Unknown(_) => false,
    }
}

pub(in crate::protocol::resource_record) fn same_rdata(left: &RData, right: &RData) -> bool {
    match (left, right) {
        (RData::DNAME(left), RData::DNAME(right))
        | (RData::CNAME(left), RData::CNAME(right))
        | (RData::MD(left), RData::MD(right))
        | (RData::MF(left), RData::MF(right))
        | (RData::MB(left), RData::MB(right))
        | (RData::MG(left), RData::MG(right))
        | (RData::MR(left), RData::MR(right))
        | (RData::NS(left), RData::NS(right))
        | (RData::PTR(left), RData::PTR(right)) => left.eq_dns(right),

        (
            RData::MINFO {
                rmailbx: left_rmailbx,
                emailbx: left_emailbx,
            },
            RData::MINFO {
                rmailbx: right_rmailbx,
                emailbx: right_emailbx,
            },
        ) => left_rmailbx.eq_dns(right_rmailbx) && left_emailbx.eq_dns(right_emailbx),
        (
            RData::MX {
                preference: left_preference,
                exchange: left_exchange,
            },
            RData::MX {
                preference: right_preference,
                exchange: right_exchange,
            },
        ) => left_preference == right_preference && left_exchange.eq_dns(right_exchange),
        (
            RData::SRV {
                priority: left_priority,
                weight: left_weight,
                port: left_port,
                target: left_target,
            },
            RData::SRV {
                priority: right_priority,
                weight: right_weight,
                port: right_port,
                target: right_target,
            },
        ) => {
            left_priority == right_priority
                && left_weight == right_weight
                && left_port == right_port
                && left_target.eq_dns(right_target)
        }
        (
            RData::SOA {
                mname: left_mname,
                rname: left_rname,
                serial: left_serial,
                refresh: left_refresh,
                retry: left_retry,
                expire: left_expire,
                minimum: left_minimum,
            },
            RData::SOA {
                mname: right_mname,
                rname: right_rname,
                serial: right_serial,
                refresh: right_refresh,
                retry: right_retry,
                expire: right_expire,
                minimum: right_minimum,
            },
        ) => {
            left_mname.eq_dns(right_mname)
                && left_rname.eq_dns(right_rname)
                && left_serial == right_serial
                && left_refresh == right_refresh
                && left_retry == right_retry
                && left_expire == right_expire
                && left_minimum == right_minimum
        }
        (RData::RRSIG(left), RData::RRSIG(right)) => {
            left.type_covered == right.type_covered
                && left.algorithm == right.algorithm
                && left.labels == right.labels
                && left.original_ttl == right.original_ttl
                && left.signature_expiration == right.signature_expiration
                && left.signature_inception == right.signature_inception
                && left.key_tag == right.key_tag
                && left.signer_name.eq_dns(&right.signer_name)
                && left.signature == right.signature
        }
        (RData::NSEC(left), RData::NSEC(right)) => {
            left.next_domain_name.eq_dns(&right.next_domain_name)
                && left.type_bitmap == right.type_bitmap
        }
        (RData::CAA(left), RData::CAA(right)) => {
            left.flags == right.flags && left.tag == right.tag && left.value == right.value
        }
        _ => left == right,
    }
}

fn txt_wire_len(strings: &[Vec<u8>]) -> Result<usize, RecordValidationError> {
    if strings.is_empty() {
        return Err(RecordValidationError::EmptyTxt);
    }
    let mut length = 0usize;
    for string in strings {
        validate_character_string(string)?;
        length = length.saturating_add(1 + string.len());
    }
    Ok(length)
}

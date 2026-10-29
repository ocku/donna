use std::path::PathBuf;

use crate::DomainName;
use crate::constants::character_string::MAX_OCTETS;

use super::MasterError;

pub(super) fn name_from_presentation(
    value: &str,
    origin: Option<&DomainName>,
) -> Result<DomainName, MasterError> {
    match value {
        "." => Ok(DomainName::root()),
        "@" => origin
            .cloned()
            .ok_or_else(|| MasterError::new("@ used without an origin")),
        _ => {
            DomainName::from_labels(resolve_presentation_labels(value, origin)?).map_err(Into::into)
        }
    }
}

fn resolve_presentation_labels(
    value: &str,
    origin: Option<&DomainName>,
) -> Result<Vec<Vec<u8>>, MasterError> {
    let bytes = value.as_bytes();
    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut index = 0;
    let mut quoted = false;
    let mut absolute = false;

    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\\' => {
                index += 1;
                label.push(decode_escape(bytes, &mut index)?);
            }
            b'"' => {
                quoted = !quoted;
                index += 1;
            }
            b'.' if !quoted => {
                if label.is_empty() {
                    return Err(MasterError::new("empty domain-name label"));
                }
                labels.push(std::mem::take(&mut label));
                index += 1;
                absolute = index == bytes.len();
            }
            _ => {
                if !(0x21..=0x7e).contains(&byte)
                    && !(quoted && matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    return Err(MasterError::new(
                        "non-printable and non-ASCII domain-name octets must use \\DDD escapes",
                    ));
                }
                label.push(byte);
                index += 1;
            }
        }
    }

    if quoted {
        return Err(MasterError::new("unterminated quoted domain-name label"));
    }
    if !absolute {
        if label.is_empty() {
            return Err(MasterError::new("empty domain-name label"));
        }
        labels.push(label);
        let origin = origin
            .ok_or_else(|| MasterError::new("relative domain name used without an origin"))?;
        labels.extend(origin.as_ref().iter().cloned());
    }

    Ok(labels)
}

pub(super) fn validate_character_string(value: &[u8], label: &str) -> Result<(), MasterError> {
    if value.len() > MAX_OCTETS {
        return Err(MasterError::new(format!("{label} exceeds 255 octets")));
    }
    Ok(())
}

pub(super) fn decode_character_string(value: &str) -> Result<Vec<u8>, MasterError> {
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while let Some(&byte) = bytes.get(index) {
        index += 1;
        output.push(if byte == b'\\' {
            decode_escape(bytes, &mut index)?
        } else {
            byte
        });
    }

    Ok(output)
}

fn decode_escape(bytes: &[u8], index: &mut usize) -> Result<u8, MasterError> {
    let byte = *bytes
        .get(*index)
        .ok_or_else(|| MasterError::new("dangling escape"))?;

    if !byte.is_ascii_digit() {
        *index += 1;
        return Ok(byte);
    }

    let digits = bytes
        .get(*index..*index + 3)
        .filter(|digits| digits.iter().all(u8::is_ascii_digit))
        .ok_or_else(|| MasterError::new("decimal escape must contain exactly three digits"))?;
    *index += 3;

    let value = u16::from(digits[0] - b'0') * 100
        + u16::from(digits[1] - b'0') * 10
        + u16::from(digits[2] - b'0');
    u8::try_from(value).map_err(|_| MasterError::new("decimal escape exceeds 255"))
}

pub(super) fn bytes_to_path(bytes: &[u8]) -> Result<PathBuf, MasterError> {
    let path = std::str::from_utf8(bytes)
        .map_err(|_| MasterError::new("include filename is not UTF-8"))?;
    Ok(PathBuf::from(path))
}

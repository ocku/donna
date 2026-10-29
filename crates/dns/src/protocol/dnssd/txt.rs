use super::*;

/// One parsed DNS-SD TXT key/value item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtProperty {
    /// Key octets, preserving presentation case.
    pub key: Vec<u8>,
    /// Optional value after `=`; `None` is a boolean attribute.
    pub value: Option<Vec<u8>>,
}

/// Parses an RFC 6763 TXT RR, retaining the first occurrence of each
/// case-insensitive key.
///
/// # Errors
///
/// Returns an error for an invalid nonempty key. An empty TXT string and an
/// absent TXT RR both represent an empty attribute set; duplicate keys after
/// the first are silently ignored as required for clients.
pub fn parse_service_txt(strings: &[Vec<u8>]) -> Result<Vec<TxtProperty>, DnsSdError> {
    let mut seen = HashSet::<Vec<u8>>::new();
    let mut output = Vec::with_capacity(strings.len());
    for string in strings {
        if string.is_empty() {
            continue;
        }
        let split = string.iter().position(|octet| *octet == b'=');
        let (key, value) = split.map_or((string.as_slice(), None), |index| {
            (&string[..index], Some(string[index + 1..].to_vec()))
        });
        if key.is_empty()
            || !key
                .iter()
                .all(|octet| matches!(octet, 0x20..=0x7e) && *octet != b'=')
        {
            return Err(DnsSdError::InvalidTxtKey);
        }
        let folded = key.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
        if !seen.insert(folded) {
            continue;
        }
        output.push(TxtProperty {
            key: key.to_vec(),
            value,
        });
    }
    Ok(output)
}

use super::*;

/// A malformed NSEC3 matching or coverage proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nsec3ProofError {
    /// The NSEC3 owner is not exactly one hash label below the zone.
    InvalidOwner,
    /// The NSEC3 owner label is not valid unpadded Base32hex.
    InvalidOwnerHash,
    /// Owner and next-owner hashes use different lengths.
    HashLengthMismatch,
    /// Hash calculation failed or exceeded the configured work bound.
    Hash(Nsec3HashError),
}

impl fmt::Display for Nsec3ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOwner => {
                formatter.write_str("NSEC3 owner is not one hash label below the zone")
            }
            Self::InvalidOwnerHash => formatter.write_str("invalid NSEC3 owner Base32hex hash"),
            Self::HashLengthMismatch => {
                formatter.write_str("NSEC3 owner and next-owner hash lengths differ")
            }
            Self::Hash(error) => write!(formatter, "NSEC3 hash failed: {error}"),
        }
    }
}

impl std::error::Error for Nsec3ProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Hash(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Nsec3HashError> for Nsec3ProofError {
    fn from(error: Nsec3HashError) -> Self {
        Self::Hash(error)
    }
}

/// The records establishing an RFC 5155 closest-encloser proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3ClosestEncloserProof {
    /// Closest provable encloser of the queried name.
    pub closest_encloser: DomainName,
    /// Index of the NSEC3 record matching [`Self::closest_encloser`].
    pub matching_record: usize,
    /// Index of the NSEC3 record covering the next-closer name.
    pub covering_record: usize,
}

/// A response does not contain a usable RFC 5155 closest-encloser proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nsec3ClosestEncloserError {
    /// The queried name is not at or below the stated zone.
    QueryOutsideZone,
    /// No supported, correctly flagged NSEC3 records exist for the zone and
    /// class.
    NoUsableRecords,
    /// Usable NSEC3 records use different algorithms, iterations, or salts.
    InconsistentParameters,
    /// A supported NSEC3 record has malformed proof data.
    MalformedRecord(Nsec3ProofError),
    /// No matching-encloser and covering-next-closer pair was found.
    MissingProof,
    /// The matching closest-encloser bitmap could be replayed from below a
    /// delegation or DNAME.
    InvalidClosestEncloser,
}

impl fmt::Display for Nsec3ClosestEncloserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueryOutsideZone => formatter.write_str("query name is outside the NSEC3 zone"),
            Self::NoUsableRecords => {
                formatter.write_str("response has no usable NSEC3 records for the zone")
            }
            Self::InconsistentParameters => {
                formatter.write_str("NSEC3 proof records use inconsistent parameters")
            }
            Self::MalformedRecord(error) => write!(formatter, "malformed NSEC3 proof: {error}"),
            Self::MissingProof => formatter.write_str("NSEC3 closest-encloser proof is missing"),
            Self::InvalidClosestEncloser => {
                formatter.write_str("NSEC3 closest encloser is not authoritative for the name")
            }
        }
    }
}

impl std::error::Error for Nsec3ClosestEncloserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedRecord(error) => Some(error),
            _ => None,
        }
    }
}

/// Finds and validates an RFC 5155 closest-encloser proof in `records`.
///
/// Unknown NSEC3 hash algorithms and records with undefined flag bits are
/// ignored as required by RFC 5155. Supported records for the selected zone
/// and class must use one coherent parameter set. The returned indices refer
/// to `records` and allow a caller to associate already-validated RRSIGs with
/// the two proof records.
///
/// # Errors
///
/// Returns an error when the query is outside the zone, the proof is missing
/// or malformed, proof parameters disagree, or hashing exceeds
/// `maximum_iterations`.
pub fn find_nsec3_closest_encloser(
    records: &[ResourceRecord],
    zone: &DomainName,
    class: crate::ClassType,
    qname: &DomainName,
    maximum_iterations: u16,
) -> Result<Nsec3ClosestEncloserProof, Nsec3ClosestEncloserError> {
    if !qname.is_descendant_of(zone) {
        return Err(Nsec3ClosestEncloserError::QueryOutsideZone);
    }

    let mut usable = Vec::new();
    let mut parameters: Option<(u8, u16, &[u8])> = None;
    for (index, record) in records.iter().enumerate() {
        let RData::NSEC3(nsec3) = &record.rdata else {
            continue;
        };
        if record.rtype != crate::RecordType::NSEC3
            || record.class != class
            || nsec3.hash_algorithm != 1
            || nsec3.flags & !Nsec3::OPT_OUT_FLAG != 0
        {
            continue;
        }
        if !record.name.is_descendant_of(zone) {
            continue;
        }
        let owner_hash = nsec3_owner_hash(&record.name, zone)
            .map_err(Nsec3ClosestEncloserError::MalformedRecord)?;
        if owner_hash.len() != nsec3.next_hashed_owner_name.len() {
            return Err(Nsec3ClosestEncloserError::MalformedRecord(
                Nsec3ProofError::HashLengthMismatch,
            ));
        }
        nsec3
            .hash_name(zone, maximum_iterations)
            .map_err(Nsec3ProofError::from)
            .map_err(Nsec3ClosestEncloserError::MalformedRecord)?;
        let current = (
            nsec3.hash_algorithm,
            nsec3.iterations,
            nsec3.salt.as_slice(),
        );
        if let Some(expected) = parameters {
            if current != expected {
                return Err(Nsec3ClosestEncloserError::InconsistentParameters);
            }
        } else {
            parameters = Some(current);
        }
        usable.push((index, record, nsec3));
    }
    if usable.is_empty() {
        return Err(Nsec3ClosestEncloserError::NoUsableRecords);
    }

    let qlabels = qname.as_ref();
    let zone_label_count = zone.as_ref().len();
    for dropped_labels in 1..=qlabels.len() - zone_label_count {
        let closest_encloser = DomainName::from_labels(qlabels[dropped_labels..].to_vec())
            .expect("a suffix of a valid domain name is valid");
        let next_closer = DomainName::from_labels(qlabels[dropped_labels - 1..].to_vec())
            .expect("a suffix of a valid domain name is valid");
        let matching = usable.iter().find(|(_, record, nsec3)| {
            nsec3
                .matches_name(&record.name, zone, &closest_encloser, maximum_iterations)
                .unwrap_or(false)
        });
        let covering = usable.iter().find(|(_, record, nsec3)| {
            nsec3
                .covers_name(&record.name, zone, &next_closer, maximum_iterations)
                .unwrap_or(false)
        });
        let (Some(&(matching_record, _, matching_nsec3)), Some(&(covering_record, _, _))) =
            (matching, covering)
        else {
            continue;
        };
        let bitmap = matching_nsec3.type_bitmap.as_ref();
        let has_dname = bitmap.is_some_and(|bitmap| bitmap.contains(39));
        let invalid_delegation = bitmap.is_some_and(|bitmap| {
            bitmap.contains(u16::from(crate::RecordType::NS))
                && !bitmap.contains(u16::from(crate::RecordType::SOA))
        });
        if has_dname || invalid_delegation {
            return Err(Nsec3ClosestEncloserError::InvalidClosestEncloser);
        }
        return Ok(Nsec3ClosestEncloserProof {
            closest_encloser,
            matching_record,
            covering_record,
        });
    }
    Err(Nsec3ClosestEncloserError::MissingProof)
}

pub(super) fn nsec3_hash(
    name: &DomainName,
    algorithm: u8,
    iterations: u16,
    salt: &[u8],
    maximum_iterations: u16,
) -> Result<Vec<u8>, Nsec3HashError> {
    nsec3_hash_fixed(name, algorithm, iterations, salt, maximum_iterations)
        .map(|digest| digest.to_vec())
}

pub(super) fn nsec3_hash_fixed(
    name: &DomainName,
    algorithm: u8,
    iterations: u16,
    salt: &[u8],
    maximum_iterations: u16,
) -> Result<[u8; 20], Nsec3HashError> {
    nsec3_hash_labels_fixed(
        name.as_ref(),
        algorithm,
        iterations,
        salt,
        maximum_iterations,
    )
}

// Labels are always a suffix of an already validated DomainName.
pub(super) fn nsec3_hash_labels_fixed(
    labels: &[Vec<u8>],
    algorithm: u8,
    iterations: u16,
    salt: &[u8],
    maximum_iterations: u16,
) -> Result<[u8; 20], Nsec3HashError> {
    if algorithm != 1 {
        return Err(Nsec3HashError::UnsupportedAlgorithm { algorithm });
    }
    if iterations > maximum_iterations {
        return Err(Nsec3HashError::TooManyIterations {
            iterations,
            maximum: maximum_iterations,
        });
    }
    let maximum_salt_length = usize::from(u8::MAX);
    if salt.len() > maximum_salt_length {
        return Err(Nsec3HashError::SaltTooLong { length: salt.len() });
    }
    // A validated domain name and a wire-format salt each fit 255 octets.
    // Include every label length and the terminal root, folding ASCII only.
    let mut canonical = [0; 2 * u8::MAX as usize];
    let mut length = 0;
    for label in labels {
        canonical[length] = label.len() as u8;
        length += 1;
        for octet in label {
            canonical[length] = octet.to_ascii_lowercase();
            length += 1;
        }
    }
    canonical[length] = 0;
    length += 1;
    canonical[length..length + salt.len()].copy_from_slice(salt);
    use sha1::Digest;
    let mut digest = sha1::Sha1::digest(&canonical[..length + salt.len()]);
    if iterations != 0 {
        canonical[20..20 + salt.len()].copy_from_slice(salt);
        for _ in 0..iterations {
            canonical[..20].copy_from_slice(&digest[..]);
            digest = sha1::Sha1::digest(&canonical[..20 + salt.len()]);
        }
    }
    let mut output = [0; 20];
    output.copy_from_slice(&digest[..]);
    Ok(output)
}

pub(super) fn base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for &octet in bytes {
        accumulator = (accumulator << 8) | u32::from(octet);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
        accumulator &= (1_u32 << bits) - 1;
    }
    if bits != 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

pub(super) fn nsec3_owner_hash(
    owner: &DomainName,
    zone: &DomainName,
) -> Result<Vec<u8>, Nsec3ProofError> {
    let owner_labels = owner.as_ref();
    let zone_labels = zone.as_ref();
    if owner_labels.len() != zone_labels.len() + 1
        || !owner_labels[1..]
            .iter()
            .zip(zone_labels)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    {
        return Err(Nsec3ProofError::InvalidOwner);
    }
    decode_base32hex_label(&owner_labels[0]).ok_or(Nsec3ProofError::InvalidOwnerHash)
}

pub(super) fn decode_base32hex_label(value: &[u8]) -> Option<Vec<u8>> {
    if value.is_empty() || value.contains(&b'=') {
        return None;
    }
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    for &octet in value {
        let digit = match octet.to_ascii_uppercase() {
            b'0'..=b'9' => octet - b'0',
            uppercase @ b'A'..=b'V' => uppercase - b'A' + 10,
            _ => return None,
        };
        accumulator = (accumulator << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1_u32 << bits) - 1;
        }
    }
    (bits < 5 && accumulator == 0 && !output.is_empty()).then_some(output)
}

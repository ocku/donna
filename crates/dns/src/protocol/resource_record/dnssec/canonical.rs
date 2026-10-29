use super::*;

/// A failure to construct RFC 4034 canonical RRSIG input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RrsigDataError {
    /// No covered record was supplied.
    EmptyRrset,
    /// The RRSIG Type Covered does not identify the supplied RRset.
    TypeCoveredMismatch,
    /// Records do not share an owner, class, and type.
    MixedRrset,
    /// Query-only or transaction-only records cannot form a signed zone RRset.
    TransientType,
    /// The RRSIG Labels field exceeds the owner name's label count.
    TooManyLabels {
        /// Labels field from the RRSIG.
        labels: u8,
        /// Number of labels in the expanded owner name.
        owner_labels: usize,
    },
    /// Two records have identical canonical RDATA.
    DuplicateRecord,
    /// A covered record is invalid for ordinary wire encoding.
    InvalidRecord(RecordValidationError),
    /// Canonical RDATA exceeds its two-octet length field.
    RDataTooLong {
        /// Canonical RDATA length in octets.
        length: usize,
    },
}

impl fmt::Display for RrsigDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRrset => formatter.write_str("an RRSIG must cover a nonempty RRset"),
            Self::TypeCoveredMismatch => {
                formatter.write_str("RRSIG Type Covered does not match the RRset")
            }
            Self::MixedRrset => formatter.write_str("covered records do not form one RRset"),
            Self::TransientType => {
                formatter.write_str("query-only and transaction-only records cannot be signed")
            }
            Self::TooManyLabels {
                labels,
                owner_labels,
            } => write!(
                formatter,
                "RRSIG Labels value {labels} exceeds owner label count {owner_labels}"
            ),
            Self::DuplicateRecord => formatter.write_str("canonical RRset contains a duplicate"),
            Self::InvalidRecord(error) => write!(formatter, "invalid covered record: {error}"),
            Self::RDataTooLong { length } => {
                write!(
                    formatter,
                    "canonical RDATA length {length} exceeds {}",
                    u16::MAX
                )
            }
        }
    }
}

impl std::error::Error for RrsigDataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRecord(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) fn signed_owner(owner: &DomainName, labels: u8) -> Result<DomainName, RrsigDataError> {
    let labels = usize::from(labels);
    let owner_labels = owner.as_ref().len();
    if labels > owner_labels {
        return Err(RrsigDataError::TooManyLabels {
            labels: labels as u8,
            owner_labels,
        });
    }
    if labels == owner_labels {
        return Ok(owner.clone());
    }
    let mut result = Vec::with_capacity(labels + 1);
    result.push(b"*".to_vec());
    result.extend_from_slice(&owner.as_ref()[owner_labels - labels..]);
    DomainName::from_labels(result).map_err(|_| RrsigDataError::TooManyLabels {
        labels: labels as u8,
        owner_labels,
    })
}

pub(super) fn write_canonical_name(name: &DomainName, output: &mut Vec<u8>) {
    for label in name.as_ref() {
        output.push(label.len() as u8);
        output.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    output.push(0);
}

fn write_uncompressed_name(name: &DomainName, output: &mut Vec<u8>) {
    for label in name.as_ref() {
        output.push(label.len() as u8);
        output.extend_from_slice(label);
    }
    output.push(0);
}

pub(super) fn canonical_rdata(rdata: &RData) -> Result<Vec<u8>, RrsigDataError> {
    let mut output = Vec::new();
    match rdata {
        RData::A(address) => output.extend_from_slice(&address.octets()),
        RData::AAAA(address) => output.extend_from_slice(&address.octets()),
        RData::DNAME(name)
        | RData::CNAME(name)
        | RData::MD(name)
        | RData::MF(name)
        | RData::MB(name)
        | RData::MG(name)
        | RData::MR(name)
        | RData::NS(name)
        | RData::PTR(name) => write_canonical_name(name, &mut output),
        RData::NULL(bytes) | RData::Unknown(bytes) => output.extend_from_slice(bytes),
        RData::WKS {
            address,
            protocol,
            bitmap,
        } => {
            output.extend_from_slice(&address.octets());
            output.push(*protocol);
            output.extend_from_slice(bitmap);
        }
        RData::HINFO { cpu, os } => {
            write_character_string(cpu, &mut output);
            write_character_string(os, &mut output);
        }
        RData::MINFO { rmailbx, emailbx } => {
            write_canonical_name(rmailbx, &mut output);
            write_canonical_name(emailbx, &mut output);
        }
        RData::MX {
            preference,
            exchange,
        } => {
            output.extend_from_slice(&preference.to_be_bytes());
            write_canonical_name(exchange, &mut output);
        }
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            output.extend_from_slice(&priority.to_be_bytes());
            output.extend_from_slice(&weight.to_be_bytes());
            output.extend_from_slice(&port.to_be_bytes());
            write_canonical_name(target, &mut output);
        }
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            write_canonical_name(mname, &mut output);
            write_canonical_name(rname, &mut output);
            for value in [serial, refresh, retry, expire, minimum] {
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
        RData::TXT(strings) => {
            for string in strings {
                write_character_string(string, &mut output);
            }
        }
        RData::SIG(sig) => {
            output.extend_from_slice(&sig.type_covered.to_be_bytes());
            output.push(sig.algorithm);
            output.push(sig.labels);
            output.extend_from_slice(&sig.original_ttl.to_be_bytes());
            output.extend_from_slice(&sig.signature_expiration.to_be_bytes());
            output.extend_from_slice(&sig.signature_inception.to_be_bytes());
            output.extend_from_slice(&sig.key_tag.to_be_bytes());
            write_canonical_name(&sig.signer_name, &mut output);
            output.extend_from_slice(&sig.signature);
        }
        RData::KEY(key) => {
            output.extend_from_slice(&key.flags.to_be_bytes());
            output.push(key.protocol);
            output.push(key.algorithm);
            output.extend_from_slice(&key.public_key);
        }
        RData::DS(ds) => {
            output.extend_from_slice(&ds.key_tag.to_be_bytes());
            output.push(ds.algorithm);
            output.push(ds.digest_type);
            output.extend_from_slice(&ds.digest);
        }
        RData::RRSIG(rrsig) => {
            output.extend_from_slice(&rrsig.type_covered.to_be_bytes());
            output.push(rrsig.algorithm);
            output.push(rrsig.labels);
            output.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
            output.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
            output.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
            output.extend_from_slice(&rrsig.key_tag.to_be_bytes());
            write_canonical_name(&rrsig.signer_name, &mut output);
            output.extend_from_slice(&rrsig.signature);
        }
        RData::NSEC(nsec) => {
            // RFC 6840 section 5.1 corrects RFC 4034: unlike other embedded
            // domain names, NSEC's next-domain name is not lowercased.
            write_uncompressed_name(&nsec.next_domain_name, &mut output);
            write_type_bitmap(&nsec.type_bitmap, &mut output);
        }
        RData::DNSKEY(dnskey) => output.extend_from_slice(&dnskey.rdata_octets()),
        RData::NSEC3(nsec3) => {
            output.push(nsec3.hash_algorithm);
            output.push(nsec3.flags);
            output.extend_from_slice(&nsec3.iterations.to_be_bytes());
            output.push(nsec3.salt.len() as u8);
            output.extend_from_slice(&nsec3.salt);
            output.push(nsec3.next_hashed_owner_name.len() as u8);
            output.extend_from_slice(&nsec3.next_hashed_owner_name);
            if let Some(type_bitmap) = &nsec3.type_bitmap {
                write_type_bitmap(type_bitmap, &mut output);
            }
        }
        RData::NSEC3PARAM(parameters) => {
            output.push(parameters.hash_algorithm);
            output.push(parameters.flags);
            output.extend_from_slice(&parameters.iterations.to_be_bytes());
            output.push(parameters.salt.len() as u8);
            output.extend_from_slice(&parameters.salt);
        }
        RData::TLSA(association) | RData::SMIMEA(association) => {
            output.push(association.certificate_usage);
            output.push(association.selector);
            output.push(association.matching_type);
            output.extend_from_slice(&association.association_data);
        }
        RData::CAA(caa) => {
            output.push(caa.flags);
            output.push(caa.tag.len() as u8);
            output.extend_from_slice(&caa.tag);
            output.extend_from_slice(&caa.value);
        }
        RData::CSYNC(csync) => {
            output.extend_from_slice(&csync.soa_serial.to_be_bytes());
            output.extend_from_slice(&csync.flags.to_be_bytes());
            write_type_bitmap(&csync.type_bitmap, &mut output);
        }
        RData::OPT(_) | RData::TSIG(_) => return Err(RrsigDataError::TransientType),
    }
    Ok(output)
}

fn write_character_string(value: &[u8], output: &mut Vec<u8>) {
    output.push(value.len() as u8);
    output.extend_from_slice(value);
}

fn write_type_bitmap(bitmap: &TypeBitmap, output: &mut Vec<u8>) {
    let mut offset = 0;
    while offset < bitmap.wire_codes().len() {
        let window = (bitmap.wire_codes()[offset] >> 8) as u8;
        let start = offset;
        while offset < bitmap.wire_codes().len()
            && (bitmap.wire_codes()[offset] >> 8) as u8 == window
        {
            offset += 1;
        }
        let low = bitmap.wire_codes()[offset - 1] as u8;
        let length = usize::from(low / 8) + 1;
        output.push(window);
        output.push(length as u8);
        let bitmap_start = output.len();
        output.resize(bitmap_start + length, 0);
        for code in &bitmap.wire_codes()[start..offset] {
            let low = *code as u8;
            output[bitmap_start + usize::from(low / 8)] |= 0x80 >> (low % 8);
        }
    }
}

pub(crate) fn canonical_name_cmp(left: &DomainName, right: &DomainName) -> Ordering {
    for (left, right) in left.as_ref().iter().rev().zip(right.as_ref().iter().rev()) {
        let ordering = left
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(right.iter().map(u8::to_ascii_lowercase));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.as_ref().len().cmp(&right.as_ref().len())
}

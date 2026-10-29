use crate::RData;
use crate::protocol::validate_rdata_forwarded;
use crate::wire::{Encoder, Result};

use super::{encode_type_bitmap, validation_error_to_wire};

pub(crate) fn encode_rdata(rdata: &RData, encoder: &mut Encoder) -> Result<()> {
    // Message encoding forwards received metadata as well as local data.
    // Keep received advisory algorithm bytes intact; local OPT
    // construction policy is enforced by the strict message builder.
    validate_rdata_forwarded(rdata).map_err(validation_error_to_wire)?;
    encode_validated_rdata(rdata, encoder)
}

/// The caller has validated this immutable RDATA through either the standalone
/// encoder above or ResourceRecord::validate_for_forwarding.
pub(crate) fn encode_validated_rdata(rdata: &RData, encoder: &mut Encoder) -> Result<()> {
    match rdata {
        RData::A(address) => encoder.write_exact(&address.octets()),
        RData::AAAA(address) => encoder.write_exact(&address.octets()),
        RData::DNAME(name) => encoder.write_uncompressed_name(name),
        RData::CNAME(name)
        | RData::NS(name)
        | RData::MD(name)
        | RData::MF(name)
        | RData::MB(name)
        | RData::MG(name)
        | RData::MR(name)
        | RData::PTR(name) => encoder.write_name(name)?,
        RData::NULL(bytes) => encoder.write_exact(bytes),
        RData::WKS {
            address,
            protocol,
            bitmap,
        } => {
            encoder.write_exact(&address.octets());
            encoder.write_u8(*protocol);
            encoder.write_exact(bitmap);
        }
        RData::HINFO { cpu, os } => {
            encoder.write_character_string(cpu)?;
            encoder.write_character_string(os)?;
        }
        RData::MINFO { rmailbx, emailbx } => {
            encoder.write_name(rmailbx)?;
            encoder.write_name(emailbx)?;
        }
        RData::MX {
            preference,
            exchange,
        } => {
            encoder.write_u16(*preference);
            encoder.write_name(exchange)?;
        }
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            encoder.write_u16(*priority);
            encoder.write_u16(*weight);
            encoder.write_u16(*port);
            encoder.write_uncompressed_name(target);
        }
        RData::TXT(strings) => {
            if strings.is_empty() {
                return Err(crate::wire::WireError::InvalidRData {
                    record_type: "TXT",
                    detail: "requires at least one character-string",
                });
            }
            for string in strings {
                encoder.write_character_string(string)?;
            }
        }
        RData::SIG(sig) => {
            encoder.write_u16(sig.type_covered);
            encoder.write_u8(sig.algorithm);
            encoder.write_u8(sig.labels);
            encoder.write_u32(sig.original_ttl);
            encoder.write_u32(sig.signature_expiration);
            encoder.write_u32(sig.signature_inception);
            encoder.write_u16(sig.key_tag);
            encoder.write_uncompressed_name(&sig.signer_name);
            encoder.write_exact(&sig.signature);
        }
        RData::KEY(key) => {
            encoder.write_u16(key.flags);
            encoder.write_u8(key.protocol);
            encoder.write_u8(key.algorithm);
            encoder.write_exact(&key.public_key);
        }
        RData::DS(ds) => {
            encoder.write_u16(ds.key_tag);
            encoder.write_u8(ds.algorithm);
            encoder.write_u8(ds.digest_type);
            encoder.write_exact(&ds.digest);
        }
        RData::RRSIG(rrsig) => {
            encoder.write_u16(rrsig.type_covered);
            encoder.write_u8(rrsig.algorithm);
            encoder.write_u8(rrsig.labels);
            encoder.write_u32(rrsig.original_ttl);
            encoder.write_u32(rrsig.signature_expiration);
            encoder.write_u32(rrsig.signature_inception);
            encoder.write_u16(rrsig.key_tag);
            encoder.write_uncompressed_name(&rrsig.signer_name);
            encoder.write_exact(&rrsig.signature);
        }
        RData::NSEC(nsec) => {
            encoder.write_uncompressed_name(&nsec.next_domain_name);
            encode_type_bitmap(&nsec.type_bitmap, encoder);
        }
        RData::DNSKEY(dnskey) => {
            encoder.write_u16(dnskey.flags);
            encoder.write_u8(dnskey.protocol);
            encoder.write_u8(dnskey.algorithm);
            encoder.write_exact(&dnskey.public_key);
        }
        RData::NSEC3(nsec3) => {
            encoder.write_u8(nsec3.hash_algorithm);
            encoder.write_u8(nsec3.flags);
            encoder.write_u16(nsec3.iterations);
            encoder.write_u8(nsec3.salt.len() as u8);
            encoder.write_exact(&nsec3.salt);
            encoder.write_u8(nsec3.next_hashed_owner_name.len() as u8);
            encoder.write_exact(&nsec3.next_hashed_owner_name);
            if let Some(type_bitmap) = &nsec3.type_bitmap {
                encode_type_bitmap(type_bitmap, encoder);
            }
        }
        RData::NSEC3PARAM(parameters) => {
            encoder.write_u8(parameters.hash_algorithm);
            encoder.write_u8(parameters.flags);
            encoder.write_u16(parameters.iterations);
            encoder.write_u8(parameters.salt.len() as u8);
            encoder.write_exact(&parameters.salt);
        }
        RData::TLSA(association) | RData::SMIMEA(association) => {
            encoder.write_u8(association.certificate_usage);
            encoder.write_u8(association.selector);
            encoder.write_u8(association.matching_type);
            encoder.write_exact(&association.association_data);
        }
        RData::OPT(options) => {
            for option in options {
                let length = u16::try_from(option.data.len()).map_err(|_| {
                    crate::wire::WireError::LengthOverflow {
                        field: "EDNS option data",
                        length: option.data.len(),
                        maximum: u16::MAX as usize,
                    }
                })?;
                encoder.write_u16(option.code);
                encoder.write_u16(length);
                encoder.write_exact(&option.data);
            }
        }
        RData::CAA(caa) => {
            encoder.write_u8(caa.flags);
            encoder.write_u8(caa.tag.len() as u8);
            encoder.write_exact(&caa.tag);
            encoder.write_exact(&caa.value);
        }
        RData::CSYNC(csync) => {
            encoder.write_u32(csync.soa_serial);
            encoder.write_u16(csync.flags);
            encode_type_bitmap(&csync.type_bitmap, encoder);
        }
        RData::TSIG(tsig) => {
            encoder.write_uncompressed_name(&tsig.algorithm);
            encoder.write_u48(tsig.time_signed);
            encoder.write_u16(tsig.fudge);
            encoder.write_u16(tsig.mac.len() as u16);
            encoder.write_exact(&tsig.mac);
            encoder.write_u16(tsig.original_id);
            encoder.write_u16(tsig.error.into());
            encoder.write_u16(tsig.other_data.len() as u16);
            encoder.write_exact(&tsig.other_data);
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
            encoder.write_name(mname)?;
            encoder.write_name(rname)?;
            encoder.write_u32(*serial);
            encoder.write_u32(*refresh);
            encoder.write_u32(*retry);
            encoder.write_u32(*expire);
            encoder.write_u32(*minimum);
        }
        RData::Unknown(bytes) => encoder.write_exact(bytes),
    }
    Ok(())
}

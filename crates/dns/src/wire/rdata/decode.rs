use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::is_valid_caa_property_tag;
use crate::wire::{Decoder, Result, WireError, decode_name, decode_uncompressed_name};
use crate::{
    Caa, CertificateAssociation, ClassType, Csync, Dnskey, Ds, EdnsOption, Key, Nsec, Nsec3,
    Nsec3param, RData, RecordType, Rrsig, Sig, Tsig, TsigErrorCode,
};

use super::{CharacterStringReader, decode_type_bitmap, validate_wks_bitmap};

pub(crate) fn decode_rdata(
    record_type: RecordType,
    class: ClassType,
    decoder: &mut Decoder<'_>,
    length: usize,
) -> Result<RData> {
    decoder.with_limit(length, |decoder| match record_type {
        RecordType::A | RecordType::AAAA | RecordType::WKS | RecordType::SRV
            if class != ClassType::IN =>
        {
            Ok(RData::Unknown(
                decoder.read_exact(decoder.remaining())?.to_vec(),
            ))
        }
        RecordType::Unknown(_) => Ok(RData::Unknown(
            decoder.read_exact(decoder.remaining())?.to_vec(),
        )),
        RecordType::A => {
            let bytes = decoder.read_exact(4)?;
            Ok(RData::A(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        RecordType::AAAA => {
            let bytes = decoder.read_exact(16)?;
            Ok(RData::AAAA(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).expect("slice length is checked"),
            )))
        }
        RecordType::NS => Ok(RData::NS(decode_name(decoder)?)),
        RecordType::MD => Ok(RData::MD(decode_name(decoder)?)),
        RecordType::MF => Ok(RData::MF(decode_name(decoder)?)),
        RecordType::CNAME => Ok(RData::CNAME(decode_name(decoder)?)),
        RecordType::DNAME => Ok(RData::DNAME(decode_uncompressed_name(
            decoder,
            "DNAME",
            "target name must not use compression",
        )?)),
        RecordType::MB => Ok(RData::MB(decode_name(decoder)?)),
        RecordType::MG => Ok(RData::MG(decode_name(decoder)?)),
        RecordType::MR => Ok(RData::MR(decode_name(decoder)?)),
        RecordType::NULL => Ok(RData::NULL(
            decoder.read_exact(decoder.remaining())?.to_vec(),
        )),
        RecordType::WKS => {
            let bytes = decoder.read_exact(4)?;
            let protocol = decoder.read_u8()?;
            let bitmap = decoder.read_exact(decoder.remaining())?.to_vec();
            validate_wks_bitmap(&bitmap)?;
            Ok(RData::WKS {
                address: Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                protocol,
                bitmap,
            })
        }
        RecordType::PTR => Ok(RData::PTR(decode_name(decoder)?)),
        RecordType::HINFO => Ok(RData::HINFO {
            cpu: decoder.read_character_string()?,
            os: decoder.read_character_string()?,
        }),
        RecordType::MINFO => Ok(RData::MINFO {
            rmailbx: decode_name(decoder)?,
            emailbx: decode_name(decoder)?,
        }),
        RecordType::MX => Ok(RData::MX {
            preference: decoder.read_u16()?,
            exchange: decode_name(decoder)?,
        }),
        RecordType::SRV => Ok(RData::SRV {
            priority: decoder.read_u16()?,
            weight: decoder.read_u16()?,
            port: decoder.read_u16()?,
            target: decode_uncompressed_name(
                decoder,
                "SRV",
                "target name must not use compression",
            )?,
        }),
        RecordType::TXT => {
            if decoder.remaining() == 0 {
                return Err(crate::wire::WireError::InvalidRData {
                    record_type: "TXT",
                    detail: "requires at least one character-string",
                });
            }
            let mut strings = Vec::new();
            while decoder.remaining() != 0 {
                strings.push(decoder.read_character_string()?);
            }
            Ok(RData::TXT(strings))
        }
        RecordType::SIG => Ok(RData::SIG(Sig {
            type_covered: decoder.read_u16()?,
            algorithm: decoder.read_u8()?,
            labels: decoder.read_u8()?,
            original_ttl: decoder.read_u32()?,
            signature_expiration: decoder.read_u32()?,
            signature_inception: decoder.read_u32()?,
            key_tag: decoder.read_u16()?,
            signer_name: decode_uncompressed_name(
                decoder,
                "SIG",
                "signer name must not use compression",
            )?,
            signature: decoder.read_exact(decoder.remaining())?.to_vec(),
        })),
        RecordType::KEY => Ok(RData::KEY(Key {
            flags: decoder.read_u16()?,
            protocol: decoder.read_u8()?,
            algorithm: decoder.read_u8()?,
            public_key: decoder.read_exact(decoder.remaining())?.to_vec(),
        })),
        RecordType::DS => Ok(RData::DS(Ds {
            key_tag: decoder.read_u16()?,
            algorithm: decoder.read_u8()?,
            digest_type: decoder.read_u8()?,
            digest: decoder.read_exact(decoder.remaining())?.to_vec(),
        })),
        RecordType::RRSIG => Ok(RData::RRSIG(Rrsig {
            type_covered: decoder.read_u16()?,
            algorithm: decoder.read_u8()?,
            labels: decoder.read_u8()?,
            original_ttl: decoder.read_u32()?,
            signature_expiration: decoder.read_u32()?,
            signature_inception: decoder.read_u32()?,
            key_tag: decoder.read_u16()?,
            signer_name: decode_uncompressed_name(
                decoder,
                "RRSIG",
                "signer name must not use compression",
            )?,
            signature: decoder.read_exact(decoder.remaining())?.to_vec(),
        })),
        RecordType::NSEC => Ok(RData::NSEC(Nsec {
            next_domain_name: decode_uncompressed_name(
                decoder,
                "NSEC",
                "next domain name must not use compression",
            )?,
            type_bitmap: decode_type_bitmap(decoder, "NSEC")?,
        })),
        RecordType::DNSKEY => Ok(RData::DNSKEY(Dnskey {
            flags: decoder.read_u16()?,
            protocol: decoder.read_u8()?,
            algorithm: decoder.read_u8()?,
            public_key: decoder.read_exact(decoder.remaining())?.to_vec(),
        })),
        RecordType::NSEC3 => {
            let hash_algorithm = decoder.read_u8()?;
            let flags = decoder.read_u8()?;
            let iterations = decoder.read_u16()?;
            let salt_length = usize::from(decoder.read_u8()?);
            let salt = decoder.read_exact(salt_length)?.to_vec();
            let hash_length = usize::from(decoder.read_u8()?);
            if hash_length == 0 {
                return Err(WireError::InvalidRData {
                    record_type: "NSEC3",
                    detail: "next hashed owner name must not be empty",
                });
            }
            let next_hashed_owner_name = decoder.read_exact(hash_length)?.to_vec();
            let type_bitmap = if decoder.remaining() == 0 {
                None
            } else {
                Some(decode_type_bitmap(decoder, "NSEC3")?)
            };
            Ok(RData::NSEC3(Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner_name,
                type_bitmap,
            }))
        }
        RecordType::NSEC3PARAM => {
            let hash_algorithm = decoder.read_u8()?;
            let flags = decoder.read_u8()?;
            let iterations = decoder.read_u16()?;
            let salt_length = usize::from(decoder.read_u8()?);
            let salt = decoder.read_exact(salt_length)?.to_vec();
            Ok(RData::NSEC3PARAM(Nsec3param {
                hash_algorithm,
                flags,
                iterations,
                salt,
            }))
        }
        RecordType::TLSA | RecordType::SMIMEA => {
            let association = CertificateAssociation {
                certificate_usage: decoder.read_u8()?,
                selector: decoder.read_u8()?,
                matching_type: decoder.read_u8()?,
                association_data: decoder.read_exact(decoder.remaining())?.to_vec(),
            };
            Ok(if record_type == RecordType::TLSA {
                RData::TLSA(association)
            } else {
                RData::SMIMEA(association)
            })
        }
        RecordType::OPT => {
            let mut options = Vec::new();
            while decoder.remaining() != 0 {
                let code = decoder.read_u16()?;
                let length = usize::from(decoder.read_u16()?);
                let data = decoder.read_exact(length)?.to_vec();
                options.push(EdnsOption { code, data });
            }
            Ok(RData::OPT(options))
        }
        RecordType::CAA => {
            let flags = decoder.read_u8()?;
            let tag_length = usize::from(decoder.read_u8()?);
            if tag_length == 0 {
                return Err(WireError::InvalidRData {
                    record_type: "CAA",
                    detail: "property tag must not be empty",
                });
            }
            let tag = decoder.read_exact(tag_length)?.to_vec();
            if !is_valid_caa_property_tag(&tag) {
                return Err(WireError::InvalidRData {
                    record_type: "CAA",
                    detail: "property tag must contain only ASCII letters and digits",
                });
            }
            let value = decoder.read_exact(decoder.remaining())?.to_vec();
            Ok(RData::CAA(Caa { flags, tag, value }))
        }
        RecordType::CSYNC => {
            let soa_serial = decoder.read_u32()?;
            let flags = decoder.read_u16()?;
            let type_bitmap = decode_type_bitmap(decoder, "CSYNC")?;
            Ok(RData::CSYNC(Csync {
                soa_serial,
                flags,
                type_bitmap,
            }))
        }
        RecordType::TSIG => {
            let algorithm = decode_uncompressed_name(
                decoder,
                "TSIG",
                "algorithm name must not use compression",
            )?;
            let time_signed = decoder.read_u48()?;
            let fudge = decoder.read_u16()?;
            let mac_length = usize::from(decoder.read_u16()?);
            let mac = decoder.read_exact(mac_length)?.to_vec();
            let original_id = decoder.read_u16()?;
            let error = TsigErrorCode::from(decoder.read_u16()?);
            let other_length = usize::from(decoder.read_u16()?);
            let other_data = decoder.read_exact(other_length)?.to_vec();
            Ok(RData::TSIG(Tsig {
                algorithm,
                time_signed,
                fudge,
                mac,
                original_id,
                error,
                other_data,
            }))
        }
        RecordType::SOA => Ok(RData::SOA {
            mname: decode_name(decoder)?,
            rname: decode_name(decoder)?,
            serial: decoder.read_u32()?,
            refresh: decoder.read_u32()?,
            retry: decoder.read_u32()?,
            expire: decoder.read_u32()?,
            minimum: decoder.read_u32()?,
        }),
    })
}

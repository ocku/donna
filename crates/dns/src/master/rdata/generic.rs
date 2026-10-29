use super::MasterError;
use crate::{ClassType, RData, RecordType};

pub(super) fn parse_generic_rdata(fields: &[String]) -> Result<RData, MasterError> {
    Ok(RData::Unknown(parse_generic_bytes(fields)?))
}

fn parse_generic_bytes(fields: &[String]) -> Result<Vec<u8>, MasterError> {
    if fields.len() < 2 || fields[0] != "\\#" {
        return Err(MasterError::new(
            "unknown RR types require RFC 3597 \\# length hexadecimal RDATA",
        ));
    }
    let declared = fields[1]
        .parse::<usize>()
        .map_err(|_| MasterError::new("invalid generic RDATA length"))?;
    if declared > usize::from(u16::MAX) {
        return Err(MasterError::new("generic RDATA exceeds 65535 octets"));
    }

    let mut bytes = Vec::with_capacity(declared);
    for word in &fields[2..] {
        if word.is_empty()
            || word.len() % 2 != 0
            || !word.as_bytes().iter().all(u8::is_ascii_hexdigit)
        {
            return Err(MasterError::new(
                "generic RDATA words must contain an even number of hexadecimal digits",
            ));
        }
        for pair in word.as_bytes().as_chunks::<2>().0 {
            let pair = std::str::from_utf8(pair).expect("ASCII hex is valid UTF-8");
            bytes.push(
                u8::from_str_radix(pair, 16)
                    .expect("a pair of validated hexadecimal digits fits in one octet"),
            );
        }
    }
    if bytes.len() != declared {
        return Err(MasterError::new(format!(
            "generic RDATA declares {declared} octets but supplies {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

pub(super) fn decode_structured_generic(
    rtype: RecordType,
    class: ClassType,
    fields: &[String],
) -> Result<RData, MasterError> {
    let bytes = parse_generic_bytes(fields)?;
    let mut decoder = crate::wire::Decoder::new_uncompressed(&bytes);
    crate::wire::decode_rdata(rtype, class, &mut decoder, bytes.len())
        .map_err(|error| MasterError::new(format!("invalid generic {rtype:?} RDATA: {error}")))
}

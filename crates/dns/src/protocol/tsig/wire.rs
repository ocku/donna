use crate::wire::{
    Decoder, WireError, decode_header, decode_question, decode_record, decode_update_record,
};
use crate::{
    ClassType, DomainName, FromWire, Message, OpCode, QClassType, RData, RecordType,
    ResourceRecord, Tsig,
};

use super::TsigAuthenticationError;

pub(super) fn ensure_no_tsig(message: &Message) -> Result<(), TsigAuthenticationError> {
    if message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .any(|record| {
            record.rtype == RecordType::TSIG
                || matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0())
        })
    {
        Err(TsigAuthenticationError::AlreadySigned)
    } else {
        Ok(())
    }
}

pub(super) fn tsig_record(name: DomainName, tsig: Tsig) -> ResourceRecord {
    ResourceRecord {
        name,
        rtype: RecordType::TSIG,
        class: ClassType::Unknown(255),
        ttl: 0,
        rdata: RData::TSIG(tsig),
    }
}

pub(super) fn standard_mac_input(
    prior_mac: Option<&[u8]>,
    unsigned_wire: &[u8],
    record: &ResourceRecord,
) -> Vec<u8> {
    let RData::TSIG(tsig) = &record.rdata else {
        unreachable!("TSIG input requires TSIG RDATA")
    };
    let mut input = Vec::new();
    if let Some(mac) = prior_mac {
        input.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        input.extend_from_slice(mac);
    }
    input.extend_from_slice(unsigned_wire);
    append_canonical_name(&mut input, &record.name);
    input.extend_from_slice(&255_u16.to_be_bytes());
    input.extend_from_slice(&0_u32.to_be_bytes());
    append_canonical_name(&mut input, &tsig.algorithm);
    append_u48(&mut input, tsig.time_signed);
    input.extend_from_slice(&tsig.fudge.to_be_bytes());
    input.extend_from_slice(&u16::from(tsig.error).to_be_bytes());
    input.extend_from_slice(&(tsig.other_data.len() as u16).to_be_bytes());
    input.extend_from_slice(&tsig.other_data);
    input
}

pub(super) fn stream_mac_input(
    prior_mac: &[u8],
    pending_wire: &[u8],
    current_unsigned_wire: &[u8],
    tsig: &Tsig,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        2 + prior_mac.len() + pending_wire.len() + current_unsigned_wire.len() + 8,
    );
    input.extend_from_slice(&(prior_mac.len() as u16).to_be_bytes());
    input.extend_from_slice(prior_mac);
    input.extend_from_slice(pending_wire);
    input.extend_from_slice(current_unsigned_wire);
    append_u48(&mut input, tsig.time_signed);
    input.extend_from_slice(&tsig.fudge.to_be_bytes());
    input
}

fn append_canonical_name(output: &mut Vec<u8>, name: &DomainName) {
    for label in name.as_ref() {
        output.push(label.len() as u8);
        output.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    output.push(0);
}

fn append_u48(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes()[2..]);
}

pub(super) fn check_time(tsig: &Tsig, now: u64) -> Result<(), TsigAuthenticationError> {
    let fudge = u64::from(tsig.fudge);
    if now < tsig.time_signed.saturating_sub(fudge) || now > tsig.time_signed.saturating_add(fudge)
    {
        Err(TsigAuthenticationError::BadTime)
    } else {
        Ok(())
    }
}

pub(super) struct SplitTsig {
    pub(super) message: Message,
    pub(super) record: ResourceRecord,
    pub(super) unsigned_wire: Vec<u8>,
}

pub(super) fn split_tsig(wire: &[u8]) -> Result<SplitTsig, TsigAuthenticationError> {
    let message = Message::from_wire(wire).map_err(TsigAuthenticationError::Wire)?;
    if message
        .answers
        .iter()
        .chain(&message.authorities)
        .any(|record| record.rtype == RecordType::TSIG)
        || message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
            .any(|record| matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0()))
    {
        return Err(TsigAuthenticationError::InvalidPlacement);
    }
    let indexes = message
        .additionals
        .iter()
        .enumerate()
        .filter_map(|(index, record)| (record.rtype == RecordType::TSIG).then_some(index))
        .collect::<Vec<_>>();
    if indexes.is_empty() {
        return Err(TsigAuthenticationError::MissingTsig);
    }
    if indexes.len() != 1 || indexes[0] + 1 != message.additionals.len() {
        return Err(TsigAuthenticationError::InvalidPlacement);
    }
    let record = message.additionals[indexes[0]].clone();
    record.validate().map_err(|_| {
        TsigAuthenticationError::Wire(WireError::InvalidRData {
            record_type: "TSIG",
            detail: "fixed record fields are invalid",
        })
    })?;
    let RData::TSIG(tsig) = &record.rdata else {
        return Err(TsigAuthenticationError::Wire(WireError::InvalidRData {
            record_type: "TSIG",
            detail: "TYPE does not contain TSIG RDATA",
        }));
    };
    if (!message.headers.qr
        && (tsig.error != crate::TsigErrorCode::NoError || tsig.original_id != message.headers.id))
        || (message.headers.qr
            && ((tsig.error == crate::TsigErrorCode::BadTime && tsig.other_data.len() != 6)
                || (tsig.error != crate::TsigErrorCode::BadTime && !tsig.other_data.is_empty())))
    {
        return Err(TsigAuthenticationError::InvalidOtherData);
    }

    let tsig_start = last_additional_start(wire)?;
    let mut unsigned_wire = wire[..tsig_start].to_vec();
    unsigned_wire[..2].copy_from_slice(&tsig.original_id.to_be_bytes());
    let additional_count = u16::from_be_bytes([unsigned_wire[10], unsigned_wire[11]]);
    let unsigned_count = additional_count
        .checked_sub(1)
        .ok_or(TsigAuthenticationError::InvalidPlacement)?;
    unsigned_wire[10..12].copy_from_slice(&unsigned_count.to_be_bytes());
    Ok(SplitTsig {
        message,
        record,
        unsigned_wire,
    })
}

fn last_additional_start(wire: &[u8]) -> Result<usize, TsigAuthenticationError> {
    let mut decoder = Decoder::new(wire);
    let (headers, counts) = decode_header(&mut decoder).map_err(TsigAuthenticationError::Wire)?;
    let questions = (0..counts.questions)
        .map(|_| decode_question(&mut decoder))
        .collect::<Result<Vec<_>, _>>()
        .map_err(TsigAuthenticationError::Wire)?;
    let zone_class = questions
        .first()
        .and_then(|question| match question.qclass {
            QClassType::Class(class) => Some(class),
            QClassType::ANY | QClassType::Unknown(_) => None,
        });
    for _ in 0..counts.answers {
        if headers.opcode == OpCode::Update {
            decode_update_record(&mut decoder, zone_class, true)
        } else {
            decode_record(&mut decoder)
        }
        .map_err(TsigAuthenticationError::Wire)?;
    }
    for _ in 0..counts.authorities {
        if headers.opcode == OpCode::Update {
            decode_update_record(&mut decoder, zone_class, false)
        } else {
            decode_record(&mut decoder)
        }
        .map_err(TsigAuthenticationError::Wire)?;
    }
    let mut last = None;
    for _ in 0..counts.additionals {
        last = Some(decoder.position());
        decode_record(&mut decoder).map_err(TsigAuthenticationError::Wire)?;
    }
    last.ok_or(TsigAuthenticationError::MissingTsig)
}

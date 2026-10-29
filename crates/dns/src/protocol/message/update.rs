use crate::{
    ClassType, Message, MessageValidationError, QClassType, RCode, RData, RecordType,
    ResourceRecord,
};

use super::{QueryType, QuestionValidationError};

const NONE_CLASS: u16 = 254;
const ANY_CLASS: u16 = 255;
const ANY_TYPE: u16 = 255;

pub(crate) fn validate_update_message(
    message: &Message,
    locally_authored: bool,
) -> Result<(), MessageValidationError> {
    message
        .validate()
        .map_err(MessageValidationError::SectionTooLong)?;

    if locally_authored
        && (message.headers.aa
            || message.headers.tc
            || message.headers.rd
            || message.headers.ra
            || message.headers.ad
            || message.headers.cd
            || (!message.headers.qr && message.headers.rcode != RCode::Ok))
    {
        return Err(MessageValidationError::InvalidUpdateMessage);
    }

    validate_additionals(message, locally_authored)?;

    // RFC 2136 section 3.8 permits a response to omit every copied request
    // section. Transaction metadata such as OPT and TSIG may still be present;
    // there is no zone class available in that form, and none is needed to
    // validate those records.
    if message.headers.qr
        && message.questions.is_empty()
        && message.answers.is_empty()
        && message.authorities.is_empty()
    {
        return Ok(());
    }

    let [zone] = message.questions.as_slice() else {
        return Err(MessageValidationError::InvalidUpdateMessage);
    };
    zone.validate_wire().map_err(|error| {
        let (field, value) = match error {
            QuestionValidationError::NonCanonicalQueryType { value } => ("ZTYPE", value),
            QuestionValidationError::NonCanonicalQueryClass { value } => ("ZCLASS", value),
        };
        MessageValidationError::InvalidQuestion {
            index: 0,
            field,
            value,
        }
    })?;
    let QClassType::Class(zone_class) = zone.qclass else {
        return Err(MessageValidationError::InvalidUpdateMessage);
    };
    if zone.qtype != QueryType::SOA {
        return Err(MessageValidationError::InvalidUpdateMessage);
    }

    for record in &message.answers {
        if !record.name.is_descendant_of(&zone.qname)
            || !valid_prerequisite(record, zone_class, locally_authored)
        {
            return Err(MessageValidationError::InvalidUpdateMessage);
        }
    }
    for record in &message.authorities {
        if !record.name.is_descendant_of(&zone.qname)
            || !valid_update(record, zone_class, locally_authored)
        {
            return Err(MessageValidationError::InvalidUpdateMessage);
        }
    }

    Ok(())
}

fn validate_additionals(
    message: &Message,
    locally_authored: bool,
) -> Result<(), MessageValidationError> {
    let opt_count = message
        .additionals
        .iter()
        .filter(|record| record.rtype == RecordType::OPT)
        .count();
    if opt_count > 1 {
        return Err(MessageValidationError::MultipleOpt);
    }
    for (index, record) in message.additionals.iter().enumerate() {
        validate_data_record(record, locally_authored).map_err(|error| {
            MessageValidationError::InvalidRecord {
                section: "additional",
                index,
                error,
            }
        })?;
    }
    if locally_authored && !message.headers.qr && message.extended_rcode() != 0 {
        return Err(MessageValidationError::ExtendedRcodeInRequest);
    }

    Ok(())
}

fn valid_prerequisite(
    record: &ResourceRecord,
    zone_class: ClassType,
    locally_authored: bool,
) -> bool {
    match record.class {
        ClassType::Unknown(ANY_CLASS | NONE_CLASS) => {
            record.ttl == 0
                && matches!(&record.rdata, RData::Unknown(bytes) if bytes.is_empty())
                && valid_prerequisite_type(record.rtype)
        }
        class if class == zone_class => {
            record.ttl == 0
                && valid_data_type(record.rtype)
                && validate_data_record(record, locally_authored).is_ok()
        }
        _ => false,
    }
}

fn valid_update(record: &ResourceRecord, zone_class: ClassType, locally_authored: bool) -> bool {
    match record.class {
        class if class == zone_class => {
            valid_data_type(record.rtype) && validate_data_record(record, locally_authored).is_ok()
        }
        ClassType::Unknown(ANY_CLASS) => {
            record.ttl == 0
                && matches!(&record.rdata, RData::Unknown(bytes) if bytes.is_empty())
                && valid_prerequisite_type(record.rtype)
        }
        ClassType::Unknown(NONE_CLASS) => {
            if record.ttl != 0 || !valid_data_type(record.rtype) {
                return false;
            }
            let mut data_record = record.clone();
            data_record.class = zone_class;
            validate_data_record(&data_record, locally_authored).is_ok()
        }
        _ => false,
    }
}

fn valid_prerequisite_type(rtype: RecordType) -> bool {
    matches!(rtype, RecordType::Unknown(ANY_TYPE)) || valid_data_type(rtype)
}

fn valid_data_type(rtype: RecordType) -> bool {
    !rtype.is_meta_type() && !matches!(rtype, RecordType::Unknown(0 | 128..=255 | u16::MAX))
}

fn validate_data_record(
    record: &ResourceRecord,
    locally_authored: bool,
) -> Result<(), crate::RecordValidationError> {
    if locally_authored {
        record.validate_locally_authored()
    } else {
        record.validate()
    }
}

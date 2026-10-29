use crate::protocol::resource_record::{same_record, same_rrset_key};
use crate::{Message, MessageValidationError, QClassType, RCode, RecordType, ResourceRecord};

use super::{QueryType, QuestionValidationError};

pub(crate) fn validate_notify_message(
    message: &Message,
    locally_authored: bool,
) -> Result<(), MessageValidationError> {
    message
        .validate()
        .map_err(MessageValidationError::SectionTooLong)?;
    if (!message.headers.aa && (!message.headers.qr || message.headers.rcode == RCode::Ok))
        || message.headers.tc
        || message.headers.rd
        || message.headers.ra
        || message.headers.ad
        || message.headers.cd
        || (!message.headers.qr && message.headers.rcode != RCode::Ok)
        || (locally_authored
            && (!message.authorities.is_empty()
                || message
                    .additionals
                    .iter()
                    .any(|record| record.rtype != RecordType::TSIG)))
    {
        return Err(MessageValidationError::InvalidNotifyMessage);
    }
    if message.questions.is_empty() {
        return Err(MessageValidationError::InvalidNotifyMessage);
    }
    for (index, question) in message.questions.iter().enumerate() {
        question.validate_wire().map_err(|error| {
            let (field, value) = match error {
                QuestionValidationError::NonCanonicalQueryType { value } => ("QTYPE", value),
                QuestionValidationError::NonCanonicalQueryClass { value } => ("QCLASS", value),
            };
            MessageValidationError::InvalidQuestion {
                index,
                field,
                value,
            }
        })?;
        if question.qtype != QueryType::SOA || !matches!(question.qclass, QClassType::Class(_)) {
            return Err(MessageValidationError::InvalidNotifyMessage);
        }
    }

    if message
        .answers
        .iter()
        .any(|answer| !answer_matches_a_question(answer, message))
    {
        return Err(MessageValidationError::InvalidNotifyMessage);
    }
    if message
        .answers
        .iter()
        .chain(&message.authorities)
        .any(|record| record.rtype == RecordType::OPT)
    {
        return Err(MessageValidationError::OptOutsideAdditional);
    }
    if message
        .additionals
        .iter()
        .filter(|record| record.rtype == RecordType::OPT)
        .count()
        > 1
    {
        return Err(MessageValidationError::MultipleOpt);
    }

    for (section, records) in [
        ("answer", &message.answers),
        ("authority", &message.authorities),
        ("additional", &message.additionals),
    ] {
        let mut previous: Vec<&ResourceRecord> = Vec::new();
        for (index, record) in records.iter().enumerate() {
            let validation = if locally_authored {
                record.validate_locally_authored()
            } else {
                record.validate()
            };
            validation.map_err(|error| MessageValidationError::InvalidRecord {
                section,
                index,
                error,
            })?;
            if matches!(record.rtype, RecordType::OPT | RecordType::TSIG) {
                continue;
            }
            for &previous_record in &previous {
                if same_rrset_key(
                    record,
                    &previous_record.name,
                    previous_record.rtype,
                    previous_record.class,
                ) && (record.ttl != previous_record.ttl || same_record(previous_record, record))
                {
                    return Err(MessageValidationError::InvalidNotifyMessage);
                }
            }
            previous.push(record);
        }
    }
    Ok(())
}

fn answer_matches_a_question(answer: &ResourceRecord, message: &Message) -> bool {
    message.questions.iter().any(|question| {
        answer.name.eq_dns(&question.qname)
            && u16::from(answer.rtype) == question.qtype.value()
            && answer.class.value() == question.qclass.value()
    })
}

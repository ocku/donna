use std::collections::HashMap;

use dns::Message;

use crate::TransportError;

use super::{RrsetKey, is_padding_only_axfr_response, validated_extended_rcode};

pub(crate) struct AxfrSeriesValidator {
    question: dns::Question,
    request_questions_are_safe_to_echo: bool,
    opening_soa: Option<dns::ResourceRecord>,
    rrset_ttls: HashMap<RrsetKey, u32>,
    distinct_rrsets: usize,
    max_distinct_rrsets: usize,
    message_index: usize,
    complete: bool,
}

impl AxfrSeriesValidator {
    pub(crate) fn new(
        question: dns::Question,
        request_questions_are_safe_to_echo: bool,
        max_distinct_rrsets: usize,
    ) -> Self {
        Self {
            question,
            request_questions_are_safe_to_echo,
            opening_soa: None,
            rrset_ttls: HashMap::new(),
            distinct_rrsets: 0,
            max_distinct_rrsets,
            message_index: 0,
            complete: false,
        }
    }

    pub(crate) fn is_first_message(&self) -> bool {
        self.message_index == 0
    }

    pub(crate) fn accept(&mut self, response: &Message) -> Option<AxfrFrameStatus> {
        if self.complete || !self.valid_sections(response) {
            return None;
        }
        let extended_rcode = validated_extended_rcode(response).ok()?;
        if extended_rcode != 0 {
            if !self.valid_terminal_error(response) {
                return None;
            }
            self.message_index += 1;
            self.complete = true;
            return Some(AxfrFrameStatus::Complete);
        }
        if !self.request_questions_are_safe_to_echo || !response.headers.aa || response.headers.tc {
            return None;
        }
        if response.answers.is_empty() {
            if self.message_index == 0 || !is_padding_only_axfr_response(response) {
                return None;
            }
            self.message_index += 1;
            return Some(AxfrFrameStatus::Continue);
        }

        for (record_index, record) in response.answers.iter().enumerate() {
            match self.classify_success_record(record, record_index) {
                Some(AxfrRecordRole::Data | AxfrRecordRole::OpeningSoa) => {}
                Some(AxfrRecordRole::ClosingSoa) => {
                    if record_index + 1 != response.answers.len() {
                        return None;
                    }
                    self.message_index += 1;
                    self.complete = true;
                    return Some(AxfrFrameStatus::Complete);
                }
                None => return None,
            }
        }

        self.message_index += 1;
        Some(AxfrFrameStatus::Continue)
    }

    pub(crate) fn finish(&self) -> bool {
        self.complete && self.message_index != 0
    }

    fn valid_sections(&self, response: &Message) -> bool {
        let valid_questions = if self.request_questions_are_safe_to_echo {
            (self.message_index != 0 && response.questions.is_empty())
                || crate::same_questions(&response.questions, std::slice::from_ref(&self.question))
        } else {
            response.questions.is_empty()
        };
        response.authorities.is_empty() && valid_questions
    }

    fn valid_terminal_error(&self, response: &Message) -> bool {
        let valid_answers = match response.answers.as_slice() {
            [] => true,
            [closing] => self.opening_soa.as_ref().is_some_and(|opening| {
                closing.rtype == dns::RecordType::SOA
                    && closing.name.eq_dns(&self.question.qname)
                    && same_resource_record(opening, closing)
            }),
            _ => false,
        };

        // Preserve the Phase 2 exception: only an immediate terminal error for
        // a noncanonical request may omit the question. Canonical errors still
        // carry exactly one question, including errors after a valid prefix.
        let valid_questions = if self.request_questions_are_safe_to_echo {
            response.questions.len() == 1
        } else {
            self.message_index == 0 && response.questions.is_empty()
        };

        (self.message_index == 0 || self.opening_soa.is_some()) && valid_questions && valid_answers
    }

    fn classify_success_record(
        &mut self,
        record: &dns::ResourceRecord,
        record_index: usize,
    ) -> Option<AxfrRecordRole> {
        if validate_transfer_record(record, &self.question).is_err() {
            return None;
        }

        let key = RrsetKey::from(record);
        match self.rrset_ttls.get(&key) {
            Some(ttl) if *ttl != record.ttl => return None,
            Some(_) => {}
            None => {
                let distinct_rrsets = self.distinct_rrsets.checked_add(1)?;
                if distinct_rrsets > self.max_distinct_rrsets {
                    return None;
                }
                self.rrset_ttls.insert(key, record.ttl);
                self.distinct_rrsets = distinct_rrsets;
            }
        }

        if !self.is_apex_soa(record) {
            return Some(AxfrRecordRole::Data);
        }
        let Some(opening) = self.opening_soa.as_ref() else {
            if self.message_index != 0 || record_index != 0 {
                return None;
            }
            self.opening_soa = Some(record.clone());
            return Some(AxfrRecordRole::OpeningSoa);
        };

        same_resource_record(opening, record).then_some(AxfrRecordRole::ClosingSoa)
    }

    fn is_apex_soa(&self, record: &dns::ResourceRecord) -> bool {
        record.rtype == dns::RecordType::SOA && record.name.eq_dns(&self.question.qname)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AxfrFrameStatus {
    Continue,
    Complete,
}

#[derive(Clone, Copy)]
enum AxfrRecordRole {
    Data,
    OpeningSoa,
    ClosingSoa,
}

pub(crate) fn validate_transfer_record(
    record: &dns::ResourceRecord,
    question: &dns::Question,
) -> Result<(), TransportError> {
    let requested_class = match question.qclass {
        dns::QClassType::Class(class) => class,
        dns::QClassType::Unknown(code) => dns::ClassType::Unknown(code),
        dns::QClassType::ANY => {
            return Err(TransportError::InvalidTransfer(
                "AXFR question must name one concrete class",
            ));
        }
    };
    if record.class != requested_class {
        return Err(TransportError::InvalidTransfer(
            "record class does not match the requested zone",
        ));
    }
    if !record.name.is_descendant_of(&question.qname) {
        return Err(TransportError::InvalidTransfer(
            "record owner is outside the requested zone",
        ));
    }
    Ok(())
}

pub(crate) fn same_resource_record(
    left: &dns::ResourceRecord,
    right: &dns::ResourceRecord,
) -> bool {
    same_rr_ignoring_ttl(left, right) && left.ttl == right.ttl
}

pub(super) fn same_rr_ignoring_ttl(
    left: &dns::ResourceRecord,
    right: &dns::ResourceRecord,
) -> bool {
    left.eq_dns(right)
}

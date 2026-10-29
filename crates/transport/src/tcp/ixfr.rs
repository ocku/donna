//! Bounded IXFR serial-chain validation across response frames.
use super::*;
use std::collections::HashSet;

pub(crate) enum TransferSeriesValidator {
    Axfr(Box<AxfrSeriesValidator>),
    Ixfr(Box<IxfrSeriesValidator>),
}

impl TransferSeriesValidator {
    pub(crate) fn new(
        question: dns::Question,
        safe: bool,
        limit: usize,
        request: &Message,
    ) -> Self {
        if question.qtype == dns::QueryType::IXFR {
            Self::Ixfr(Box::new(IxfrSeriesValidator {
                question: question.clone(),
                safe,
                limit,
                keys: HashSet::new(),
                axfr: AxfrSeriesValidator::new(question, safe, limit),
                axfr_valid: true,
                opening: None,
                pending: None,
                count: 0,
                messages: 0,
                stage: Stage::Second,
                expected: request.authorities.first().and_then(serial),
                error: false,
            }))
        } else {
            Self::Axfr(Box::new(AxfrSeriesValidator::new(question, safe, limit)))
        }
    }

    pub(crate) fn prepare(
        &mut self,
        mut response: Message,
        headers: &dns::Headers,
        questions: &[dns::Question],
        request: Option<(&Message, TransportProtocol)>,
    ) -> Option<Vec<u8>> {
        match self {
            Self::Axfr(validator) => {
                prepare_axfr_response(response, headers, questions, validator, request)
            }
            Self::Ixfr(validator) => {
                if has_tsig(&response) {
                    if !authenticated_response_headers_match(headers, &response) {
                        return None;
                    }
                } else {
                    normalize_response_headers(headers, &mut response);
                    if !validator.safe {
                        response.questions.clear();
                    } else {
                        response.questions = questions.to_vec();
                    }
                    response::prepare_response_padding(&mut response, request)?;
                }
                validator.accept(&response)?;
                response
                    .into_wire_ixfr(&validator.question)
                    .ok()
                    .filter(|wire| wire.len() <= MAX_TCP_MESSAGE_OCTETS)
            }
        }
    }

    pub(crate) fn finish(&self) -> bool {
        match self {
            Self::Axfr(v) => v.finish(),
            Self::Ixfr(v) => v.finish(),
        }
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Second,
    Deletes,
    Adds,
    Fallback,
}

pub(crate) struct IxfrSeriesValidator {
    question: dns::Question,
    safe: bool,
    limit: usize,
    keys: HashSet<axfr::RrsetKey>,
    axfr: AxfrSeriesValidator,
    axfr_valid: bool,
    opening: Option<dns::ResourceRecord>,
    // Delay one record: the final SOA is a terminator, not another delta.
    pending: Option<dns::ResourceRecord>,
    count: usize,
    messages: usize,
    stage: Stage,
    expected: Option<u32>,
    error: bool,
}

impl IxfrSeriesValidator {
    fn accept(&mut self, response: &Message) -> Option<()> {
        if self.error
            || !response.authorities.is_empty()
            || !(self.messages > 0 && response.questions.is_empty()
                || (self.safe
                    && same_questions(&response.questions, std::slice::from_ref(&self.question)))
                || (!self.safe && response.questions.is_empty()))
        {
            return None;
        }
        self.axfr_valid &= self.axfr.accept(response).is_some();
        if axfr::validated_extended_rcode(response).ok()? != 0 {
            if self.messages != 0 || !response.answers.is_empty() {
                return None;
            }
            self.error = true;
            self.messages += 1;
            return Some(());
        }
        if !self.safe || !response.headers.aa || response.headers.tc {
            return None;
        }
        if response.answers.is_empty() {
            if self.messages == 0 || !axfr::is_padding_only_axfr_response(response) {
                return None;
            }
            self.messages += 1;
            return Some(());
        }
        for record in &response.answers {
            axfr::validate_transfer_record(record, &self.question).ok()?;
            self.keys.insert(axfr::RrsetKey::from(record));
            if self.keys.len() > self.limit {
                return None;
            }
            if self.opening.is_none() {
                if !self.is_soa(record) {
                    return None;
                }
                self.opening = Some(record.clone());
            } else {
                if let Some(previous) = self.pending.take() {
                    self.accept_middle(&previous)?;
                }
                self.pending = Some(record.clone());
            }
            self.count = self.count.checked_add(1)?;
        }
        self.messages += 1;
        Some(())
    }

    fn accept_middle(&mut self, record: &dns::ResourceRecord) -> Option<()> {
        let soa = self.is_soa(record);
        match self.stage {
            Stage::Second if !soa => self.stage = Stage::Fallback,
            Stage::Second => {
                if serial(record) != self.expected || self.expected.is_none() {
                    return None;
                }
                self.stage = Stage::Deletes;
            }
            Stage::Deletes if soa => {
                let new = serial(record)?;
                if dns::SerialNumber::new(self.expected?).compare(dns::SerialNumber::new(new))
                    != Some(std::cmp::Ordering::Less)
                {
                    return None;
                }
                self.expected = Some(new);
                self.stage = Stage::Adds;
            }
            Stage::Adds if soa => {
                if serial(record) != self.expected {
                    return None;
                }
                self.stage = Stage::Deletes;
            }
            Stage::Fallback if soa => return None,
            _ => {}
        }
        Some(())
    }

    fn finish(&self) -> bool {
        if self.error {
            return true;
        }
        let Some(opening) = &self.opening else {
            return false;
        };
        if self.count == 1 {
            return self
                .expected
                .zip(serial(opening))
                .is_some_and(|(requested, current)| single_soa_completes_ixfr(requested, current));
        }
        if !self
            .pending
            .as_ref()
            .is_some_and(|last| axfr::same_resource_record(opening, last))
        {
            return false;
        }
        match self.stage {
            Stage::Second | Stage::Fallback => self.axfr_valid && self.axfr.finish(),
            Stage::Adds => self.expected == serial(opening),
            Stage::Deletes => false,
        }
    }

    fn is_soa(&self, record: &dns::ResourceRecord) -> bool {
        record.rtype == dns::RecordType::SOA && record.name.eq_dns(&self.question.qname)
    }
}

pub(super) fn single_soa_completes_ixfr(requested: u32, current: u32) -> bool {
    matches!(
        dns::SerialNumber::new(current).compare(dns::SerialNumber::new(requested)),
        Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
    )
}

fn serial(record: &dns::ResourceRecord) -> Option<u32> {
    match record.rdata {
        dns::RData::SOA { serial, .. } => Some(serial),
        _ => None,
    }
}

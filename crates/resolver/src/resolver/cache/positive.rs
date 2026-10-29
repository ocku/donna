use crate::cache::positive::SelectedPositive;
use dns::{FromWire, Headers, Message, Question, ResourceRecord};
use smallvec::SmallVec;

pub(super) type AliasSelections = SmallVec<[SelectedPositive; 4]>;
pub(super) type Records<'a> = SmallVec<[(&'a ResourceRecord, u32); 8]>;

pub(in crate::resolver) struct PositiveResponse {
    pub(super) terminal: SelectedPositive,
    pub(super) aliases: AliasSelections,
    pub(super) prefix_answers: Vec<ResourceRecord>,
    pub(super) prefix_authorities: Vec<ResourceRecord>,
    pub(super) question: Question,
    pub(super) aliases_authenticated: bool,
}

impl PositiveResponse {
    pub(super) fn records(&self) -> (Records<'_>, Records<'_>) {
        let terminal_ttl = self.terminal.ttl();
        let mut answers = Records::new();
        answers.extend(self.prefix_answers.iter().map(|rr| (rr, rr.ttl)));
        // The old composer starts with terminal authorities, then appends
        // earlier-hop authorities, retaining first position/spelling and min TTL.
        let mut authorities: Records<'_> = self
            .terminal
            .authorities()
            .iter()
            .map(|rr| (rr, terminal_ttl))
            .collect();
        for record in &self.prefix_authorities {
            merge_authority(&mut authorities, record, record.ttl);
        }
        for alias in &self.aliases {
            let ttl = alias.ttl();
            answers.extend(alias.answers().iter().map(|rr| (rr, ttl)));
            for record in alias.authorities() {
                merge_authority(&mut authorities, record, ttl);
            }
        }
        answers.extend(self.terminal.answers().iter().map(|rr| (rr, terminal_ttl)));
        (answers, authorities)
    }

    pub(super) fn encode_udp(
        &self,
        request: &Message,
        maximum: usize,
        validating: bool,
    ) -> Option<dns::wire::EncodedReply> {
        let (mut answers, mut authorities) = self.records();
        let dnssec_ok = matches!(request.additionals.as_slice(),
            [opt] if opt.rtype == dns::RecordType::OPT && opt.ttl & 0x8000 != 0);
        let qtype = request
            .questions
            .first()
            .map(|question| question.qtype.value());
        let retain = |(record, _): &mut (&ResourceRecord, u32)| {
            crate::response::requested_dnssec_record(record.rtype, qtype, dnssec_ok)
        };
        if !dnssec_ok {
            answers.retain(retain);
            authorities.retain(retain);
        }
        // Selection and all cache effects have already happened. Reuse only a
        // bounded template whose complete ordered component identities match.
        if self.prefix_answers.is_empty()
            && self.prefix_authorities.is_empty()
            && !self.aliases.is_empty()
            && self.aliases.len() <= 4
            && answers.len() + authorities.len() <= 64
        {
            let selections = || self.aliases.iter().chain(std::iter::once(&self.terminal));
            let ttls: SmallVec<[u32; 16]> = answers
                .iter()
                .chain(&authorities)
                .map(|(_, ttl)| *ttl)
                .collect();
            let mut slots = self.aliases[0]
                .compositions()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let slot = &mut slots[usize::from(dnssec_ok)];
            let matching = slot.as_ref().filter(|template| {
                template.identities.len() == self.aliases.len() + 1
                    && selections()
                        .zip(&template.identities)
                        .all(|(selected, identity)| selected.matches_identity(identity))
            });
            if let Some(template) = matching {
                if let Some(reply) = template
                    .reply
                    .render_record_ttls(request, &ttls, maximum, validating)
                {
                    return Some(reply);
                }
                // An unsupported spelling, QTYPE or size uses ordinary borrowed
                // encoding without rebuilding a template for every request.
            } else {
                // Encode the selected records once, then decode only bounded
                // packets for template preparation. Large/irregular fallbacks
                // never clone arbitrary RDATA just to attempt a template.
                let encoded = dns::wire::EncodedReply::recursive_positive(
                    request,
                    &answers,
                    &authorities,
                    validating && self.aliases_authenticated && self.terminal.authenticated,
                    maximum,
                )
                .ok()
                .flatten()?;
                if encoded.as_bytes().len() > 4096 {
                    return Some(encoded);
                }
                let mut prototype = dns::Message::from_wire(encoded.as_bytes()).ok()?;
                prototype.headers.cd = false;
                prototype.headers.ad = self.aliases_authenticated && self.terminal.authenticated;
                prototype.additionals = vec![
                    dns::Edns {
                        dnssec_ok,
                        ..dns::Edns::default()
                    }
                    .into_record(),
                ];
                if let Ok(Some(reply)) =
                    dns::wire::PreparedPositiveReply::from_composed_message(&prototype)
                {
                    let template = crate::cache::positive::ComposedPositive {
                        identities: selections().map(SelectedPositive::identity).collect(),
                        reply,
                    };
                    *slot = Some(Box::new(template));
                }
                return Some(encoded);
            }
        }
        dns::wire::EncodedReply::recursive_positive(
            request,
            &answers,
            &authorities,
            validating && self.aliases_authenticated && self.terminal.authenticated,
            maximum,
        )
        .ok()
        .flatten()
    }

    pub(in crate::resolver) fn into_message(self) -> Message {
        let (answers, authorities) = {
            let (answers, authorities) = self.records();
            (materialize(&answers), materialize(&authorities))
        };
        Message {
            headers: Headers {
                qr: true,
                ad: self.aliases_authenticated && self.terminal.authenticated,
                ..Headers::default()
            },
            questions: vec![self.question],
            answers,
            authorities,
            additionals: Vec::new(),
        }
    }
}

pub(super) fn merge_authority<'a>(
    records: &mut Records<'a>,
    incoming: &'a ResourceRecord,
    ttl: u32,
) {
    if let Some((_, existing_ttl)) = records.iter_mut().find(|(record, _)| {
        record.name.eq_dns(&incoming.name)
            && record.class == incoming.class
            && record.rtype == incoming.rtype
            && record.rdata == incoming.rdata
    }) {
        *existing_ttl = (*existing_ttl).min(ttl);
    } else {
        records.push((incoming, ttl));
    }
}

fn materialize(records: &[(&ResourceRecord, u32)]) -> Vec<ResourceRecord> {
    records
        .iter()
        .map(|&(record, ttl)| {
            let mut value = record.clone();
            value.ttl = ttl;
            value
        })
        .collect()
}

/// Converts the already-touched selections at an existing ordinary boundary.
pub(super) fn materialize_aliases(
    aliases: &mut AliasSelections,
    answers: &mut Vec<ResourceRecord>,
    authorities: &mut Vec<ResourceRecord>,
) {
    answers.reserve(aliases.iter().map(|a| a.answers().len()).sum());
    authorities.reserve(aliases.iter().map(|a| a.authorities().len()).sum());
    for alias in aliases.drain(..) {
        let ttl = alias.ttl();
        answers.extend(alias.answers().iter().cloned().map(|mut rr| {
            rr.ttl = ttl;
            rr
        }));
        authorities.extend(alias.authorities().iter().cloned().map(|mut rr| {
            rr.ttl = ttl;
            rr
        }));
    }
}

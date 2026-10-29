use dns::{FromWire, Message, RCode, ResourceRecord};

use super::positive::{AliasSelections, Records, merge_authority};
use crate::cache::negative::SelectedNegative;

pub(in crate::resolver) struct NegativeResponse {
    pub(super) selected: SelectedNegative,
    pub(super) aliases: AliasSelections,
    pub(super) nameservers: smallvec::SmallVec<[ResourceRecord; 1]>,
    pub(super) question: dns::Question,
    pub(super) terminal_question: dns::Question,
    pub(super) aliases_authenticated: bool,
}

impl NegativeResponse {
    pub(super) fn encode_udp(
        &self,
        request: &Message,
        maximum: usize,
        validating: bool,
    ) -> Option<dns::wire::EncodedReply> {
        encode_udp(
            &self.selected,
            &self.aliases,
            request,
            &self.nameservers,
            maximum,
            validating && self.aliases_authenticated && self.selected.authenticated,
        )
    }

    pub(super) fn into_message(mut self) -> Message {
        let mut reply = self.selected.materialize(&self.terminal_question);
        if !reply.headers.ad || !self.aliases_authenticated {
            reply.authorities.extend(self.nameservers);
        }
        reply.headers.ad &= self.aliases_authenticated;
        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        super::positive::materialize_aliases(&mut self.aliases, &mut answers, &mut authorities);
        let mut response =
            crate::response::complete_cname_response(reply, &self.question, answers, authorities);
        response
            .authorities
            .retain(|record| crate::cache::negative::keep_authority(record, response.headers.ad));
        response
    }
}

/// Encode the same selected negative and aliases without another cache lookup.
/// Bounded templates retain weak alias identities and checked referral values;
/// current selections and per-record TTLs determine every rendered reply.
pub(super) fn encode_udp(
    selected: &SelectedNegative,
    aliases: &AliasSelections,
    request: &Message,
    nameservers: &[ResourceRecord],
    maximum: usize,
    authenticated: bool,
) -> Option<dns::wire::EncodedReply> {
    let nameservers = if authenticated { &[][..] } else { nameservers };
    // Gate before allocating any spilled reference or TTL bookkeeping.
    let terminal_count = selected.authorities().count() + nameservers.len();
    if terminal_count > 64 {
        return None;
    }
    aliases.iter().try_fold(terminal_count, |count, alias| {
        let count = count + alias.answers().len() + alias.authorities().len();
        (count <= 64).then_some(count)
    })?;
    let mut answers = Records::new();
    let mut authorities: Records<'_> = selected.authorities().collect();
    authorities.extend(nameservers.iter().map(|record| (record, record.ttl)));
    // Match complete_cname_response: terminal authority and implicit NS first,
    // then prior alias authorities, retaining first spelling/order and min TTL.
    for alias in aliases {
        let ttl = alias.ttl();
        answers.extend(alias.answers().iter().map(|record| (record, ttl)));
        for record in alias.authorities() {
            merge_authority(&mut authorities, record, ttl);
        }
    }
    if authenticated {
        authorities.retain(|(record, _)| crate::cache::negative::keep_authority(record, true));
    }
    let dnssec_ok = matches!(request.additionals.as_slice(), [opt]
        if opt.rtype == dns::RecordType::OPT && opt.ttl & 0x8000 != 0);
    let qtype = request.questions.first()?.qtype.value();
    let retain = |(record, _): &mut (&ResourceRecord, u32)| {
        crate::response::requested_dnssec_record(record.rtype, Some(qtype), dnssec_ok)
    };
    if !dnssec_ok {
        answers.retain(retain);
        authorities.retain(retain);
    }
    if aliases.len() <= 4 && selected.all_authorities_live_at_selection() {
        let ttls: smallvec::SmallVec<[u32; 16]> = answers
            .iter()
            .chain(&authorities)
            .map(|(_, ttl)| *ttl)
            .collect();
        let mut slots = selected
            .compositions()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let slot = &mut slots[usize::from(dnssec_ok)];
        let same_aliases = |template: &crate::cache::negative::ComposedNegative| {
            template.aliases.len() == aliases.len()
                && aliases
                    .iter()
                    .zip(&template.aliases)
                    .all(|(alias, identity)| alias.matches_identity(identity))
        };
        let matching = slot.as_ref().filter(|template| {
            same_aliases(template)
                && nameservers.len() == template.nameservers.len()
                && nameservers
                    .iter()
                    .zip(&template.nameservers)
                    .all(|(current, prior)| {
                        current.name == prior.name
                            && current.class == prior.class
                            && current.rtype == prior.rtype
                            && current.rdata == prior.rdata
                    })
        });
        if let Some(template) = matching {
            if let Some(reply) = template
                .reply
                .render(request, &ttls, maximum, authenticated)
            {
                return Some(reply);
            }
        } else {
            let encoded = dns::wire::EncodedReply::recursive_negative(
                request,
                &answers,
                &authorities,
                selected.rcode == RCode::NameError,
                authenticated,
                maximum,
            )
            .ok()
            .flatten()?;
            // Preparation adds an eleven-byte empty OPT to classic replies.
            // Match the constructor's actual limit before decoding; otherwise
            // an oversized packet would repeatedly attempt ineligible setup.
            let prototype_length =
                encoded
                    .as_bytes()
                    .len()
                    .saturating_add(if request.additionals.is_empty() {
                        11
                    } else {
                        0
                    });
            if selected.prepare_composition
                && aliases.iter().all(|alias| alias.frequent)
                && prototype_length <= usize::from(dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE)
                // Pin a live composition rather than rebuilding on every
                // request when multiple hot aliases share this negative.
                // The same aliases may refresh their current referral; a
                // different path takes over only after an old identity dies.
                && slot.as_ref().is_none_or(|template| {
                    if same_aliases(template) { return true; }
                    let now = std::time::Instant::now();
                    template.aliases.iter().any(|identity| !identity.is_live(now))
                })
            {
                let mut prototype = Message::from_wire(encoded.as_bytes()).ok()?;
                prototype.headers.cd = false;
                prototype.headers.ad =
                    selected.authenticated && aliases.iter().all(|a| a.authenticated);
                prototype.additionals = vec![
                    dns::Edns {
                        dnssec_ok,
                        ..dns::Edns::default()
                    }
                    .into_record(),
                ];
                if let Ok(Some(reply)) =
                    dns::wire::PreparedNegativeReply::from_composed_message(&prototype)
                {
                    *slot = Some(Box::new(crate::cache::negative::ComposedNegative {
                        aliases: aliases
                            .iter()
                            .map(crate::cache::positive::SelectedPositive::identity)
                            .collect(),
                        nameservers: nameservers.into(),
                        reply,
                    }));
                }
            }
            return Some(encoded);
        }
    }
    dns::wire::EncodedReply::recursive_negative(
        request,
        &answers,
        &authorities,
        selected.rcode == RCode::NameError,
        authenticated,
        maximum,
    )
    .ok()
    .flatten()
}

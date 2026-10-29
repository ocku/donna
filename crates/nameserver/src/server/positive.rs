use crate::{
    response::base_response,
    zone::{PositiveSelection, Zone, response::additional_address_target},
};
use dns::Message;

pub(super) fn resolve_positive(
    zone: &Zone,
    query: &Message,
    selection: &PositiveSelection<'_>,
    maximum: usize,
) -> Option<transport::ImmediateUdpResponse> {
    let mut answers = selection.references();
    if answers
        .iter()
        .any(|(record, _)| additional_address_target(record).is_some())
    {
        return None;
    }
    let dnssec_ok = query
        .edns()
        .ok()
        .flatten()
        .is_some_and(|edns| edns.dnssec_ok);
    if dnssec_ok {
        zone.append_positive_rrsig_refs(&mut answers, selection.source_indices());
    }
    let authorities = if dnssec_ok {
        zone.positive_authority_refs(&answers)?
    } else {
        smallvec::SmallVec::new()
    };
    if let Ok(Some(encoded)) =
        dns::wire::EncodedReply::authoritative_positive(query, &answers, &authorities, maximum)
    {
        return Some(transport::ImmediateUdpResponse::Encoded(encoded));
    }
    // Keep the exact selected owner projections, signatures and proofs for
    // ordinary validation/errors and whole-RRset truncation on fallback.
    let mut reply = base_response(query);
    reply.headers.aa = true;
    reply.answers = answers
        .into_iter()
        .map(|(record, owner)| {
            let mut record = record.clone();
            record.name = owner.clone();
            record
        })
        .collect();
    reply.authorities = authorities.into_iter().cloned().collect();
    Some(transport::ImmediateUdpResponse::Message(reply))
}

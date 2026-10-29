use dns::{Message, RData, RecordType, ResourceRecord};

/// Retains denial records needed by selected wildcard-expanded answer RRsets.
/// Authority records remain authority data and are never promoted to answers.
pub(crate) fn wildcard_proofs(source: &Message, answers: &[ResourceRecord]) -> Vec<ResourceRecord> {
    let signers = answers
        .iter()
        .filter_map(|record| {
            let RData::RRSIG(signature) = &record.rdata else {
                return None;
            };
            (usize::from(signature.labels) < record.name.as_ref().len())
                .then_some((&signature.signer_name, record.class))
        })
        .collect::<Vec<_>>();
    let proofs = source
        .authorities
        .iter()
        .filter(|record| {
            matches!(record.rtype, RecordType::NSEC | RecordType::NSEC3)
                && signers.iter().any(|(zone, class)| {
                    record.class == *class && record.name.is_descendant_of(zone)
                })
        })
        .collect::<Vec<_>>();
    source.authorities.iter().filter(|record| {
        proofs.iter().any(|proof| {
            record.name.eq_dns(&proof.name) && record.class == proof.class
                && (record.rtype == proof.rtype || matches!(&record.rdata, RData::RRSIG(signature) if signature.type_covered == u16::from(proof.rtype)))
        })
    }).cloned().collect()
}

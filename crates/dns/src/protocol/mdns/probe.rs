use super::*;

/// Returns whether a name belongs to the link-local `.local.` mDNS namespace.
pub fn is_local_name(name: &crate::DomainName) -> bool {
    name.as_ref()
        .last()
        .is_some_and(|label| label.eq_ignore_ascii_case(b"local"))
}

/// Returns true when a known answer suppresses retransmission of `candidate`.
pub fn known_answer_suppresses(candidate: &ResourceRecord, known: &ResourceRecord) -> bool {
    candidate.eq_dns(known) && known.ttl >= candidate.ttl.saturating_add(1) / 2
}

/// Result of RFC 6762 simultaneous-probe lexicographic tie-breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeTieBreak {
    /// Local proposed data is lexicographically later and wins.
    Win,
    /// Peer proposed data is lexicographically later and wins.
    Lose,
    /// Both proposals contain identical data.
    Equal,
}

/// Compares two probe authority sets using canonical class, type, and RDATA
/// ordering. RFC 6762 assigns the win to the lexicographically later set.
///
/// # Errors
///
/// Returns an error when either proposal contains invalid record data.
pub fn probe_tie_break(
    local: &[ResourceRecord],
    peer: &[ResourceRecord],
) -> Result<ProbeTieBreak, MdnsError> {
    let mut local = proposal_keys(local)?;
    let mut peer = proposal_keys(peer)?;
    local.sort_unstable();
    peer.sort_unstable();
    Ok(match local.cmp(&peer) {
        std::cmp::Ordering::Greater => ProbeTieBreak::Win,
        std::cmp::Ordering::Less => ProbeTieBreak::Lose,
        std::cmp::Ordering::Equal => ProbeTieBreak::Equal,
    })
}

fn proposal_keys(records: &[ResourceRecord]) -> Result<Vec<(u16, u16, Vec<u8>)>, MdnsError> {
    records
        .iter()
        .map(|record| {
            record.validate().map_err(MdnsError::InvalidRecord)?;
            let mut encoder = Encoder::new_uncompressed();
            encode_rdata(&record.rdata, &mut encoder)?;
            Ok((
                record.class.value(),
                record.rtype.into(),
                encoder.into_bytes(),
            ))
        })
        .collect()
}

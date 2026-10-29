//! Response classification and packet-completion helpers for the resolver.

mod cache_selection;
mod classification;
mod cname;
mod dname;
mod normalization;
mod wildcard_proofs;
pub(crate) use wildcard_proofs::wildcard_proofs;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

pub(crate) use cache_selection::positive_cache_entries;
pub(crate) use classification::{
    delegation_progresses, has_dname_negative_answer_metadata, has_only_negative_answer_metadata,
    has_requested_answer, has_soa_for_question, is_terminal_response, query_type_matches_record,
    validate_question,
};
pub(crate) use cname::{CnameError, append_distinct, cname_restart, complete_cname_response};
pub(crate) use dname::{DnameError, checked_substitution, prepare_substitution};
pub(crate) use normalization::normalize_response_rrsets;

/// The recursive client's existing DNSSEC stripping policy, shared by owned
/// responses, prepared cache replies and borrowed CNAME composition.
pub(crate) fn requested_dnssec_record(
    rtype: dns::RecordType,
    qtype: Option<u16>,
    dnssec_ok: bool,
) -> bool {
    dnssec_ok
        || !matches!(
            rtype,
            dns::RecordType::RRSIG | dns::RecordType::NSEC | dns::RecordType::NSEC3
        )
        || qtype == Some(u16::from(rtype))
}

#[allow(deprecated, reason = "Retain the atomic API supported by Rust 1.88.")]
pub(crate) fn consume_work(remaining_steps: &AtomicUsize) -> bool {
    remaining_steps
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |steps| {
            steps.checked_sub(1)
        })
        .is_ok()
}

pub(crate) fn schedule_retries(
    candidates: &mut Vec<SocketAddr>,
    attempts: &HashMap<SocketAddr, u8>,
    servers: impl IntoIterator<Item = SocketAddr>,
    max_attempts: Option<u8>,
) {
    let max_attempts = max_attempts.map(|attempts| attempts.max(1));
    // Candidates are popped from the end. Store retries in reverse input order
    // so every untried address is attempted first, followed by retries in input
    // order.
    let existing_count = candidates.len();
    candidates.extend(servers.into_iter().filter(|server| {
        max_attempts.is_none_or(|max_attempts| {
            attempts.get(server).copied().unwrap_or_default() < max_attempts
        })
    }));
    let retry_count = candidates.len() - existing_count;
    if retry_count == 0 {
        return;
    }
    let retry_start = candidates.len() - retry_count;
    candidates[retry_start..].reverse();
    candidates.rotate_right(retry_count);
}

#[cfg(test)]
use crate::ResolveError;
#[cfg(test)]
use dns::{ClassType, DomainName, Message, QClassType, Question, RData, ResourceRecord};

#[cfg(test)]
mod tests;

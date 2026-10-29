/// RFC 9520 section 3: at most three transmissions per server and transport.
pub(crate) const MAX_TRANSMISSIONS_PER_SERVER: u8 = 3;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use dns::{ClassType, DomainName, Edns, Headers, Message, Question, RData, ResourceRecord};

use crate::name::packed_key;
use crate::resolver::AlgorithmSignals;

pub(super) struct Referral {
    pub(super) zone: DomainName,
    pub(super) class: ClassType,
    /// Exact referral-NS addresses usable only while following this referral.
    /// This can include out-of-bailiwick sibling glue, which is deliberately
    /// excluded from `candidate_ttls` and `trusted_glue` below.
    pub(super) candidates: Vec<SocketAddr>,
    /// Cache lifetime for each trusted glue address. This remains separate
    /// from `candidates`, whose ordering is used by the current resolution.
    pub(super) candidate_ttls: Vec<(SocketAddr, Duration)>,
    pub(super) trusted_glue: Vec<ResourceRecord>,
    pub(super) name_servers: Vec<DomainName>,
    pub(super) ttl: Duration,
}

impl Referral {
    pub(super) fn matching_glue(&self, question: &Question) -> Vec<ResourceRecord> {
        let dns::QClassType::Class(class) = question.qclass else {
            return Vec::new();
        };
        self.trusted_glue
            .iter()
            .filter(|record| {
                record.name.eq_dns(&question.qname)
                    && record.class == class
                    && u16::from(record.rtype) == u16::from(question.qtype)
            })
            .cloned()
            .collect()
    }
}

pub(super) fn query(id: u16, question: &Question, edns_udp_payload_size: u16) -> Message {
    query_with_algorithm_signals(
        id,
        question,
        edns_udp_payload_size,
        &AlgorithmSignals::default(),
        false,
    )
}

pub(super) fn query_with_algorithm_signals(
    id: u16,
    question: &Question,
    edns_udp_payload_size: u16,
    algorithm_signals: &AlgorithmSignals,
    dnssec_ok: bool,
) -> Message {
    let mut edns = Edns::new(edns_udp_payload_size);
    algorithm_signals.apply_to(&mut edns);
    edns.dnssec_ok |= dnssec_ok;
    let mut message = Message::builder()
        .headers(Headers {
            id,
            rd: false,
            cd: true,
            ..Headers::default()
        })
        .questions([question.clone()])
        .build()
        .expect("a one-question query is valid");
    // The OPT may contain received advisory algorithm codes. They are valid
    // for forwarding, but the local builder deliberately rejects reserved
    // codes. Attach that metadata after validating our locally built query;
    // wire encoding applies forwarding validation to the complete message.
    message.additionals.push(edns.into_record());
    message
}

/// Checks the response properties the iterative resolver relies on after a
/// successful wire decode. RRSet publication policy belongs to outbound data
/// validation and must not cause an otherwise usable inbound reply to be lost.
pub(super) fn is_correlated_response(reply: &Message, id: u16, question: &Question) -> bool {
    reply.headers.qr
        && reply.headers.opcode == dns::OpCode::Query
        && reply.headers.id == id
        && reply.questions.len() == 1
        && same_question(&reply.questions[0], question)
}

pub(super) fn is_usable_response(reply: &Message, id: u16, question: &Question) -> bool {
    !reply.headers.tc && is_correlated_response(reply, id, question)
}

fn same_question(left: &Question, right: &Question) -> bool {
    left.qname.eq_dns(&right.qname) && left.qtype == right.qtype && left.qclass == right.qclass
}

pub(super) fn referral(reply: &Message, question: &Question) -> Option<Referral> {
    // A referral is a non-authoritative, NOERROR response with no answer
    // section. RFC 2308 §2.2 gives SOA precedence over NS when distinguishing
    // a Type 1 NODATA response from a referral.
    if reply.headers.aa || reply.headers.rcode != dns::RCode::Ok || !reply.answers.is_empty() {
        return None;
    }

    let class = match question.qclass {
        dns::QClassType::Class(class) => class,
        dns::QClassType::ANY | dns::QClassType::Unknown(_) => return None,
    };
    if reply.authorities.iter().any(|record| {
        record.class == class
            && matches!(record.rdata, RData::SOA { .. })
            && question.qname.is_descendant_of(&record.name)
    }) {
        return None;
    }

    // A response can include NS records for more than one ancestor. RFC 1034
    // requires following the closest cut, not an arbitrary parent delegation.
    let zone = reply
        .authorities
        .iter()
        .filter(|record| {
            matches!(&record.rdata, RData::NS(_))
                && record.class == class
                && question.qname.is_descendant_of(&record.name)
        })
        .map(|record| &record.name)
        .max_by_key(|name| name.as_ref().len())?
        .clone();

    let mut name_servers = reply
        .authorities
        .iter()
        .filter_map(|record| match &record.rdata {
            RData::NS(name) if record.class == class && record.name.eq_dns(&zone) => {
                Some((name.clone(), received_ttl(record.ttl)))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut seen_name_servers = HashSet::with_capacity(name_servers.len());
    name_servers.retain(|(name, _)| seen_name_servers.insert(packed_key(name)));
    let ns_ttl = name_servers.iter().map(|(_, ttl)| *ttl).min()?;

    let addresses = reply
        .additionals
        .iter()
        .filter_map(|record| {
            additional_name_server_address(record, &name_servers)
                .map(|(address, ttl)| (record, address, ttl))
        })
        .collect::<Vec<_>>();
    // Exact A/AAAA records for a referral NS can seed this referral attempt,
    // including the sibling glue used by root referrals (for example, a .com
    // server whose name is below .net). Only in-bailiwick glue is trusted
    // beyond that attempt or can enter either cache.
    let mut candidates = addresses
        .iter()
        .map(|(_, address, _)| *address)
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    let trusted_addresses = addresses
        .into_iter()
        .filter(|(record, _, _)| record.name.is_descendant_of(&zone))
        .collect::<Vec<_>>();
    // Different glue RRsets can legitimately have different TTLs. Preserve
    // those lifetimes independently; when the same socket is supplied by more
    // than one RRset, it remains usable until the longest valid source expires.
    let mut candidate_ttls = HashMap::with_capacity(trusted_addresses.len());
    for (_, address, ttl) in &trusted_addresses {
        candidate_ttls
            .entry(*address)
            .and_modify(|current: &mut u32| *current = (*current).max(*ttl))
            .or_insert(*ttl);
    }
    let mut candidate_ttls = candidate_ttls
        .into_iter()
        .map(|(address, ttl)| (address, Duration::from_secs(u64::from(ttl))))
        .collect::<Vec<_>>();
    candidate_ttls.sort_unstable_by_key(|(address, _)| *address);
    let trusted_glue = trusted_addresses
        .into_iter()
        .map(|(record, _, ttl)| {
            let mut record = (*record).clone();
            record.ttl = ttl;
            record
        })
        .collect();
    let name_servers = name_servers.into_iter().map(|(name, _)| name).collect();

    Some(Referral {
        zone,
        class,
        candidates,
        candidate_ttls,
        trusted_glue,
        name_servers,
        ttl: Duration::from_secs(u64::from(ns_ttl)),
    })
}

fn additional_name_server_address(
    record: &ResourceRecord,
    name_servers: &[(DomainName, u32)],
) -> Option<(SocketAddr, u32)> {
    if record.class != ClassType::IN
        || !name_servers
            .iter()
            .any(|(name, _)| record.name.eq_dns(name))
    {
        return None;
    }
    let address = match (record.rtype, &record.rdata) {
        (dns::RecordType::A, RData::A(address)) => IpAddr::V4(*address),
        (dns::RecordType::AAAA, RData::AAAA(address)) => IpAddr::V6(*address),
        _ => return None,
    };
    Some((SocketAddr::new(address, 53), received_ttl(record.ttl)))
}

fn received_ttl(ttl: u32) -> u32 {
    if ttl & 0x8000_0000 == 0 { ttl } else { 0 }
}

#[cfg(test)]
mod tests;

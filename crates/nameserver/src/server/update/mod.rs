#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

use std::{cmp::Ordering, sync::Arc};

use dns::{
    ClassType, Headers, Message, QClassType, RCode, RData, RecordType, ResourceRecord, SerialNumber,
};
use tracing::warn;

use crate::{Zone, name::dns_name_key};

use super::{NameServer, UpdateIdentity};

const NONE_CLASS: u16 = 254;
const ANY_CLASS: u16 = 255;
const ANY_TYPE: u16 = 255;
const NXT_TYPE: u16 = 30;

mod commit;
mod operations;

use operations::{apply_operations, same_record_set, unique_records};

#[cfg(test)]
mod tests;

pub(super) async fn handle_update(
    server: &NameServer,
    request: Message,
    identity: Option<&UpdateIdentity>,
) -> Message {
    if !valid_update_envelope(&request) {
        return response(&request, RCode::FormatError);
    }

    let zone_question = &request.questions[0];
    let QClassType::Class(zone_class) = zone_question.qclass else {
        unreachable!("the update envelope requires a concrete class")
    };
    let zone_key = dns_name_key(&zone_question.qname);

    let zone_exists = {
        let zones = match server.zones.read().await {
            Ok(zones) => zones,
            Err(_) => return response(&request, RCode::ServerFailure),
        };
        zones
            .by_apex
            .get(&zone_key)
            .is_some_and(|at_apex| at_apex.iter().any(|zone| zone.class() == zone_class))
    };
    if !zone_exists {
        return response(&request, RCode::NotAuthoritative);
    }

    let authorized = match identity {
        Some(identity) => {
            server.config.update_rules.iter().any(|rule| {
                rule.identity.eq_dns(identity) && rule.zone.eq_dns(&zone_question.qname)
            }) && request.authorities.iter().all(|record| {
                server
                    .config
                    .update_rules
                    .iter()
                    .any(|rule| rule.permits(identity, &zone_question.qname, record))
            })
        }
        None => server.config.allow_insecure_updates,
    };
    if !authorized {
        return response(&request, RCode::Refused);
    }

    // Serialize only mutations to this exact zone. In particular, arbitrary
    // user persistence code must never run under the global zone-index lock.
    // The inexpensive existence and authorization checks happen first so
    // rejected traffic cannot populate the per-zone mutation map.
    let mutation = server
        .zone_mutation_lock(&zone_question.qname, zone_class)
        .await;
    let mutation_guard = mutation.lock_owned().await;
    let (current, external_snapshot) = {
        let zones = match server.zones.read().await {
            Ok(zones) => zones,
            Err(_) => return response(&request, RCode::ServerFailure),
        };
        let current = zones.by_apex.get(&zone_key).and_then(|at_apex| {
            at_apex
                .iter()
                .find(|zone| zone.class() == zone_class)
                .map(Arc::clone)
        });
        let snapshot = match &zones {
            super::storage::ZoneRead::External(snapshot) => Some(snapshot.clone()),
            super::storage::ZoneRead::BuiltIn(_) => None,
        };
        (current, snapshot)
    };
    let Some(current) = current else {
        return response(&request, RCode::NotAuthoritative);
    };

    if let Err(rcode) = validate_update(&request, &current) {
        return response(&request, rcode);
    }
    if external_snapshot.is_none() && server.config.update_persistence.is_none() {
        return response(&request, RCode::Refused);
    }

    let Some(records) = apply_operations(&current, &request.authorities) else {
        return response(&request, RCode::ServerFailure);
    };
    if records_unchanged(current.records(), &records) {
        return response(&request, RCode::Ok);
    }
    if current
        .records()
        .iter()
        .any(|record| is_current_dnssec_generated_type(record.rtype))
    {
        return response(&request, RCode::Refused);
    }
    let candidate = match Zone::from_dynamic_records(current.apex().clone(), zone_class, records) {
        Ok(zone) => Arc::new(zone),
        Err(error) => {
            warn!(%error, "dynamic update produced an invalid zone snapshot");
            return response(&request, RCode::ServerFailure);
        }
    };
    // Once durable persistence starts, the server owns the whole commit. A
    // disconnected client (and the request task cancellation that follows)
    // must not leave durable storage ahead of publication or its IXFR/NOTIFY
    // bookkeeping. The owned zone guard also preserves same-zone ordering
    // after the request future has gone away.
    let server = server.clone();
    let commit = tokio::spawn(async move {
        let _mutation_guard = mutation_guard;
        commit::publish(&server, &current, &candidate, external_snapshot).await
    });
    let rcode = commit.await.unwrap_or_else(|error| {
        warn!(%error, "dynamic update commit task failed");
        RCode::ServerFailure
    });
    response(&request, rcode)
}

fn validate_update(request: &Message, current: &Zone) -> Result<(), RCode> {
    // RFC 3007 forbids explicit NXT mutation. Donna does not expose an online
    // RFC 2535 zone-signing role, so it also refuses to mutate a legacy secure
    // zone rather than publish stale SIG/NXT data.
    if request
        .authorities
        .iter()
        .any(|record| u16::from(record.rtype) == NXT_TYPE)
        || current.records().iter().any(|record| {
            u16::from(record.rtype) == NXT_TYPE
                || matches!(&record.rdata, RData::SIG(sig) if !sig.is_sig0())
        })
    {
        return Err(RCode::Refused);
    }

    // RFC 4035 denial records and their signatures are generated data. Until
    // Donna has an online signing role, accepting direct mutations would let
    // UPDATE clients publish proofs that do not describe the resulting zone.
    if request
        .authorities
        .iter()
        .any(|record| is_current_dnssec_generated_type(record.rtype))
    {
        return Err(RCode::Refused);
    }

    if request
        .answers
        .iter()
        .chain(&request.authorities)
        .any(|record| !record.name.is_descendant_of(current.apex()))
    {
        return Err(RCode::NotZone);
    }
    if request.validate_for_forwarding().is_err() {
        return Err(RCode::FormatError);
    }

    prerequisites_hold(current, &request.answers)
}

fn valid_update_envelope(request: &Message) -> bool {
    !request.headers.qr
        && request.headers.opcode == dns::OpCode::Update
        && matches!(request.questions.as_slice(), [question]
            if question.qtype == dns::QueryType::SOA
                && matches!(question.qclass, QClassType::Class(_))
                && question.is_wire_canonical())
}

fn prerequisites_hold(zone: &Zone, prerequisites: &[ResourceRecord]) -> Result<(), RCode> {
    let mut checked_value_sets: Vec<(&dns::DomainName, RecordType)> = Vec::new();
    for prerequisite in prerequisites {
        let zone_records = || {
            zone.records()
                .iter()
                .filter(|record| record.name.eq_dns(&prerequisite.name))
        };
        match prerequisite.class {
            ClassType::Unknown(ANY_CLASS) if is_any(prerequisite.rtype) => {
                if zone_records().next().is_none() {
                    return Err(RCode::NameError);
                }
            }
            ClassType::Unknown(ANY_CLASS) => {
                if !zone_records().any(|record| record.rtype == prerequisite.rtype) {
                    return Err(RCode::NXRRSet);
                }
            }
            ClassType::Unknown(NONE_CLASS) if is_any(prerequisite.rtype) => {
                if zone_records().next().is_some() {
                    return Err(RCode::YXDomain);
                }
            }
            ClassType::Unknown(NONE_CLASS) => {
                if zone_records().any(|record| record.rtype == prerequisite.rtype) {
                    return Err(RCode::YXRRSet);
                }
            }
            class if class == zone.class() => {
                if checked_value_sets.iter().any(|(name, rtype)| {
                    name.eq_dns(&prerequisite.name) && *rtype == prerequisite.rtype
                }) {
                    continue;
                }
                checked_value_sets.push((&prerequisite.name, prerequisite.rtype));
                let expected = unique_records(
                    prerequisites
                        .iter()
                        .filter(|record| {
                            record.class == zone.class()
                                && record.name.eq_dns(&prerequisite.name)
                                && record.rtype == prerequisite.rtype
                        })
                        .cloned(),
                );
                let actual = unique_records(
                    zone_records()
                        .filter(|record| record.rtype == prerequisite.rtype)
                        .cloned(),
                );
                if !same_record_set(&expected, &actual) {
                    return Err(RCode::NXRRSet);
                }
            }
            _ => return Err(RCode::FormatError),
        }
    }
    Ok(())
}

fn records_unchanged(left: &[ResourceRecord], right: &[ResourceRecord]) -> bool {
    same_record_set(left, right)
        && left.iter().all(|record| {
            right
                .iter()
                .any(|candidate| record.eq_dns(candidate) && record.ttl == candidate.ttl)
        })
}

fn is_any(rtype: RecordType) -> bool {
    rtype == RecordType::Unknown(ANY_TYPE)
}

fn is_current_dnssec_generated_type(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM
    )
}

fn soa_serial(records: &[ResourceRecord], apex: &dns::DomainName) -> Option<u32> {
    records.iter().find_map(|record| {
        (record.name.eq_dns(apex) && record.rtype == RecordType::SOA)
            .then(|| record_soa_serial(record))
            .flatten()
    })
}

fn record_soa_serial(record: &ResourceRecord) -> Option<u32> {
    match record.rdata {
        RData::SOA { serial, .. } => Some(serial),
        _ => None,
    }
}

fn set_soa_serial(records: &mut [ResourceRecord], apex: &dns::DomainName, serial: u32) {
    let Some(soa) = records
        .iter_mut()
        .find(|record| record.name.eq_dns(apex) && record.rtype == RecordType::SOA)
    else {
        return;
    };
    if let RData::SOA {
        serial: current, ..
    } = &mut soa.rdata
    {
        *current = serial;
    }
}

fn response(request: &Message, rcode: RCode) -> Message {
    Message {
        headers: Headers {
            id: request.headers.id,
            qr: true,
            opcode: request.headers.opcode,
            rcode,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

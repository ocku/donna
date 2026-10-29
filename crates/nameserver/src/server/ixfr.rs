use std::cmp::Ordering;

use dns::{IntoWire, Message, RData, RecordType, ResourceRecord, SerialNumber};

use crate::{Zone, response::base_response};

#[derive(Clone, Debug)]
pub(super) struct IxfrDelta {
    pub(super) old_soa: ResourceRecord,
    pub(super) deleted: Vec<ResourceRecord>,
    pub(super) new_soa: ResourceRecord,
    pub(super) added: Vec<ResourceRecord>,
}

impl IxfrDelta {
    pub(super) fn between(old: &Zone, new: &Zone) -> Option<Self> {
        let old_soa = old.soa().clone();
        let new_soa = new.soa().clone();
        if SerialNumber::new(soa_serial(&old_soa)?)
            .compare(SerialNumber::new(soa_serial(&new_soa)?))
            != Some(Ordering::Less)
        {
            return None;
        }
        let old_data = old
            .records()
            .iter()
            .filter(|record| record.rtype != RecordType::SOA || !record.name.eq_dns(old.apex()));
        let new_data = new
            .records()
            .iter()
            .filter(|record| record.rtype != RecordType::SOA || !record.name.eq_dns(new.apex()));
        let deleted = old_data
            .clone()
            .filter(|record| {
                !new_data
                    .clone()
                    .any(|candidate| same_record(record, candidate))
            })
            .cloned()
            .collect();
        let added = new_data
            .filter(|record| {
                !old_data
                    .clone()
                    .any(|candidate| same_record(record, candidate))
            })
            .cloned()
            .collect();
        Some(Self {
            old_soa,
            deleted,
            new_soa,
            added,
        })
    }

    pub(super) fn old_serial(&self) -> u32 {
        soa_serial(&self.old_soa).expect("journal SOA is structured")
    }

    pub(super) fn new_serial(&self) -> u32 {
        soa_serial(&self.new_soa).expect("journal SOA is structured")
    }
}

pub(super) enum IxfrAnswer {
    Current(Message),
    Incremental(Message),
    Full,
}

pub(super) fn answer(
    query: &Message,
    zone: &Zone,
    history: &[IxfrDelta],
    udp_limit: Option<usize>,
) -> IxfrAnswer {
    let Some(client_serial) = query.authorities.first().and_then(soa_serial) else {
        return IxfrAnswer::Full;
    };
    let current_soa = zone.soa().clone();
    let current_serial = soa_serial(&current_soa).expect("validated zone has an SOA serial");
    if SerialNumber::new(client_serial).compare(SerialNumber::new(current_serial))
        != Some(Ordering::Less)
    {
        return IxfrAnswer::Current(response(query, vec![current_soa]));
    }

    let Some(start) = history
        .iter()
        .position(|delta| delta.old_serial() == client_serial)
    else {
        return fallback(query, current_soa, udp_limit);
    };
    let chain = &history[start..];
    if chain.last().map(IxfrDelta::new_serial) != Some(current_serial)
        || chain
            .windows(2)
            .any(|pair| pair[0].new_serial() != pair[1].old_serial())
    {
        return fallback(query, current_soa, udp_limit);
    }

    let mut records = vec![current_soa.clone()];
    for delta in chain {
        records.push(delta.old_soa.clone());
        records.extend(delta.deleted.iter().cloned());
        records.push(delta.new_soa.clone());
        records.extend(delta.added.iter().cloned());
    }
    records.push(current_soa.clone());
    let incremental = response(query, records);
    let incremental_len = incremental.clone().into_wire().ok().map(|wire| wire.len());
    let full_len = response(query, zone.transfer_records_iter().collect())
        .into_wire()
        .ok()
        .map(|wire| wire.len());
    if incremental_len.is_none()
        || full_len.is_some_and(|full| incremental_len.is_some_and(|ixfr| ixfr >= full))
    {
        return fallback(query, current_soa, udp_limit);
    }
    if udp_limit.is_some_and(|limit| incremental_len.is_none_or(|length| length > limit)) {
        return IxfrAnswer::Current(response(query, vec![current_soa]));
    }
    IxfrAnswer::Incremental(incremental)
}

fn fallback(query: &Message, current_soa: ResourceRecord, udp_limit: Option<usize>) -> IxfrAnswer {
    udp_limit.map_or(IxfrAnswer::Full, |_| {
        IxfrAnswer::Current(response(query, vec![current_soa]))
    })
}

fn response(query: &Message, answers: Vec<ResourceRecord>) -> Message {
    let mut response = base_response(query);
    response.headers.aa = true;
    response.answers = answers;
    response
}

fn soa_serial(record: &ResourceRecord) -> Option<u32> {
    match record.rdata {
        RData::SOA { serial, .. } => Some(serial),
        _ => None,
    }
}

fn same_record(left: &ResourceRecord, right: &ResourceRecord) -> bool {
    left.ttl == right.ttl && left.eq_dns(right)
}

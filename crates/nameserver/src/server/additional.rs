use dns::{ClassType, DomainName, Message, Question, ResourceRecord};

use crate::zone::{
    Lookup, Zone,
    response::{additional_address_target, contains_record},
};

use super::zone_index::{ZoneIndex, authoritative_zone, qclass_for_class};

pub(super) fn additional_address_records(
    zones: &ZoneIndex,
    records: &[ResourceRecord],
) -> Vec<ResourceRecord> {
    let mut additionals = Vec::new();
    for reference in records {
        let Some(target) = additional_address_target(reference) else {
            continue;
        };
        let addresses = match authoritative_address_records(zones, target, reference.class) {
            AddressRecords::Authoritative(records) => records,
            AddressRecords::Delegated | AddressRecords::Unavailable => Vec::new(),
        };
        for record in addresses {
            if !contains_record(&additionals, &record) {
                additionals.push(record);
            }
        }
    }
    additionals
}

pub(super) fn referral_additional_address_records(
    zones: &ZoneIndex,
    delegation_zone: &Zone,
    records: &[ResourceRecord],
) -> Vec<ResourceRecord> {
    let mut additionals = Vec::new();
    for reference in records {
        let Some(target) = additional_address_target(reference) else {
            continue;
        };
        let addresses = match authoritative_address_records(zones, target, reference.class) {
            AddressRecords::Authoritative(records) => records,
            AddressRecords::Delegated | AddressRecords::Unavailable => {
                delegation_zone.referral_glue_records(std::slice::from_ref(reference))
            }
        };
        for record in addresses {
            if !contains_record(&additionals, &record) {
                additionals.push(record);
            }
        }
    }
    additionals
}

enum AddressRecords {
    Authoritative(Vec<ResourceRecord>),
    Delegated,
    Unavailable,
}

fn authoritative_address_records(
    zones: &ZoneIndex,
    target: &DomainName,
    class: ClassType,
) -> AddressRecords {
    let mut question = Question {
        qname: target.clone(),
        qtype: dns::QueryType::A,
        qclass: qclass_for_class(class),
    };
    let Some(source_zone) = authoritative_zone(zones, &question) else {
        return AddressRecords::Unavailable;
    };

    let mut addresses = Vec::new();
    let mut authoritative = false;
    let mut delegated = false;
    for qtype in [dns::QueryType::A, dns::QueryType::AAAA] {
        question.qtype = qtype;
        match source_zone.lookup(&question) {
            Lookup::Answer(records) => {
                authoritative = true;
                addresses.extend(records);
            }
            Lookup::Referral(_) => delegated = true,
            Lookup::Cname { .. }
            | Lookup::Dname { .. }
            | Lookup::NameError
            | Lookup::NoData { .. } => authoritative = true,
        }
    }
    if authoritative {
        AddressRecords::Authoritative(addresses)
    } else if delegated {
        AddressRecords::Delegated
    } else {
        AddressRecords::Unavailable
    }
}

pub(super) fn append_additionals(reply: &mut Message, records: Vec<ResourceRecord>) {
    for record in records {
        if !contains_record(&reply.answers, &record)
            && !contains_record(&reply.authorities, &record)
            && !contains_record(&reply.additionals, &record)
        {
            reply.additionals.push(record);
        }
    }
}

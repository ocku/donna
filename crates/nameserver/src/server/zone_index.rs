use std::{collections::HashMap, sync::Arc};

use dns::{ClassType, DomainName, QClassType, QueryType, Question};

use crate::{
    name::{DnsNameKey, dns_name_key_into, suffixes},
    zone::Zone,
};

/// Zones grouped by their case-normalized apex for direct suffix lookup.
#[derive(Default)]
pub(super) struct ZoneIndex {
    pub(super) by_apex: HashMap<DnsNameKey, Vec<Arc<Zone>>>,
    pub(super) len: usize,
}

pub(super) fn authoritative_zone<'a>(
    zones: &'a ZoneIndex,
    question: &Question,
) -> Option<&'a Zone> {
    let mut storage = [0; 255];
    let name = dns_name_key_into(&question.qname, &mut storage);
    authoritative_zone_key(zones, question, name)
}

pub(super) fn authoritative_zone_key<'a>(
    zones: &'a ZoneIndex,
    question: &Question,
    name: &[u8],
) -> Option<&'a Zone> {
    if zones.len == 1 && question.qtype != QueryType::DS {
        let (apex, at_apex) = zones.by_apex.iter().next()?;
        return suffixes(name)
            .any(|suffix| suffix == apex.as_ref())
            .then(|| {
                at_apex
                    .iter()
                    .find(|zone| qclass_matches(question.qclass, zone.class))
            })
            .flatten()
            .map(Arc::as_ref);
    }
    // Inspect each hosted suffix once. The outermost redirect wins because
    // an ancestor DNAME occludes a hosted child; zone lookup also respects
    // intervening delegation cuts. The first matching zone is the usual
    // longest-apex answer, with a parent preferred for DS (RFC 4035 3.1.4.1).
    let mut ordinary = None;
    let mut parent = None;
    let mut redirect = None;
    for (depth, suffix) in suffixes(name).enumerate() {
        let Some(at_apex) = zones.by_apex.get(suffix) else {
            continue;
        };
        for zone in at_apex {
            if !qclass_matches(question.qclass, zone.class) {
                continue;
            }
            let zone = zone.as_ref();
            if ordinary.is_none() {
                ordinary = Some(zone);
            }
            if parent.is_none()
                && question.qtype == QueryType::DS
                && depth > 0
                && zone.is_authoritative_owner(&question.qname)
            {
                parent = Some(zone);
            }
            if zone.redirects_by_dname_key(name) {
                redirect = Some(zone);
            }
        }
    }
    redirect.or(parent).or(ordinary)
}

pub(super) fn exact_authoritative_zone(
    zones: &ZoneIndex,
    question: &Question,
) -> Option<Arc<Zone>> {
    let mut storage = [0; 255];
    zones
        .by_apex
        .get(dns_name_key_into(&question.qname, &mut storage))?
        .iter()
        .find(|zone| qclass_matches(question.qclass, zone.class))
        .cloned()
}

fn qclass_matches(qclass: QClassType, class: ClassType) -> bool {
    match qclass {
        QClassType::Class(selected) => selected == class,
        QClassType::ANY => true,
        QClassType::Unknown(code) => class.value() == code,
    }
}

pub(super) fn qclass_for_class(class: ClassType) -> QClassType {
    match class {
        ClassType::Unknown(code) => QClassType::Unknown(code),
        class => QClassType::Class(class),
    }
}

pub(super) fn closest_zones_by_class<'a>(zones: &'a ZoneIndex, name: &DomainName) -> Vec<&'a Zone> {
    let mut storage = [0; 255];
    let name = dns_name_key_into(name, &mut storage);
    let mut selected = Vec::new();
    for suffix in suffixes(name) {
        let Some(zones_at_apex) = zones.by_apex.get(suffix) else {
            continue;
        };
        for zone in zones_at_apex {
            if let Some(previous) = selected
                .iter_mut()
                .find(|selected: &&mut &Zone| selected.class == zone.class)
            {
                if zone.redirects_by_dname_key(name) {
                    *previous = zone.as_ref();
                }
            } else {
                selected.push(zone.as_ref());
            }
        }
    }
    selected
}

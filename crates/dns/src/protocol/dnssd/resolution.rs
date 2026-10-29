use super::*;

/// Source-authentication policy attached to discovered service data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySecurity {
    /// Link-local mDNS data validated by mDNS scope and conflict rules.
    LocalLink,
    /// Unicast DNS data with its DNSSEC validation result.
    Dnssec(DnssecSecurityStatus),
}

/// A completely resolved DNS-SD service instance.
#[derive(Debug, Clone)]
pub struct ResolvedService {
    /// Instance identity.
    pub instance: ServiceInstance,
    /// SRV priority.
    pub priority: u16,
    /// SRV weight.
    pub weight: u16,
    /// Service port.
    pub port: u16,
    /// Target host.
    pub target: DomainName,
    /// Parsed TXT properties.
    pub txt: Vec<TxtProperty>,
    /// Discovered IPv4 addresses.
    pub ipv4_addresses: Vec<Ipv4Addr>,
    /// Discovered IPv6 addresses.
    pub ipv6_addresses: Vec<Ipv6Addr>,
    /// Authentication context for the discovery data.
    pub security: DiscoverySecurity,
}

/// Browses and resolves one service type from a coherent record collection.
///
/// # Errors
///
/// Returns an error for a mismatched discovery security mode or malformed TXT
/// data or invalid instance labels. Incomplete instances and SRV targets declaring the service
/// unavailable (the root name) are omitted.
pub fn resolve_services(
    service_type: &ServiceType,
    domain: &DomainName,
    records: &[ResourceRecord],
    security: DiscoverySecurity,
) -> Result<Vec<ResolvedService>, DnsSdError> {
    if is_local_name(domain) != (security == DiscoverySecurity::LocalLink) {
        return Err(DnsSdError::SecurityModeMismatch);
    }
    if !is_local_name(domain)
        && !matches!(
            security,
            DiscoverySecurity::Dnssec(DnssecSecurityStatus::Secure)
        )
    {
        return Err(DnsSdError::InsecureUnicastDiscovery);
    }
    let records = records
        .iter()
        .filter(|record| record.class == ClassType::IN);
    let browse_owner = service_type.owner(domain)?;
    let mut output = Vec::new();
    for instance_owner in records.clone().filter_map(|record| match &record.rdata {
        RData::PTR(target)
            if record.rtype == RecordType::PTR && record.name.eq_dns(&browse_owner) =>
        {
            Some(target)
        }
        _ => None,
    }) {
        let Some(RData::SRV {
            priority,
            weight,
            port,
            target,
        }) = records.clone().find_map(|record| {
            (record.rtype == RecordType::SRV && record.name.eq_dns(instance_owner))
                .then_some(&record.rdata)
        })
        else {
            continue;
        };
        // RFC 2782: the root target explicitly declares no service endpoint.
        if target.as_ref().is_empty() {
            continue;
        }
        let txt = records
            .clone()
            .find_map(|record| match &record.rdata {
                RData::TXT(strings)
                    if record.rtype == RecordType::TXT && record.name.eq_dns(instance_owner) =>
                {
                    Some(strings)
                }
                _ => None,
            })
            .map_or_else(|| Ok(Vec::new()), |strings| parse_service_txt(strings))?;
        let Some(instance_label) = instance_owner.as_ref().first().cloned() else {
            continue;
        };
        let instance = ServiceInstance::new(instance_label, service_type.clone(), domain.clone())?;
        if !instance.owner()?.eq_dns(instance_owner) {
            continue;
        }
        let ipv4_addresses = records
            .clone()
            .filter_map(|record| match record.rdata {
                RData::A(address)
                    if record.rtype == RecordType::A && record.name.eq_dns(target) =>
                {
                    Some(address)
                }
                _ => None,
            })
            .collect();
        let ipv6_addresses = records
            .clone()
            .filter_map(|record| match record.rdata {
                RData::AAAA(address)
                    if record.rtype == RecordType::AAAA && record.name.eq_dns(target) =>
                {
                    Some(address)
                }
                _ => None,
            })
            .collect();
        output.push(ResolvedService {
            instance,
            priority: *priority,
            weight: *weight,
            port: *port,
            target: target.clone(),
            txt,
            ipv4_addresses,
            ipv6_addresses,
            security,
        });
    }
    Ok(output)
}

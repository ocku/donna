use std::{
    collections::HashSet,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{
    ClassType, DnssecSecurityStatus, DomainName, DomainNameError, QClassType, QueryType, Question,
    RData, RecordType, ResourceRecord, is_local_name,
};

mod error;
mod instance;
mod resolution;
mod service_type;
mod txt;

pub use error::DnsSdError;
pub use instance::ServiceInstance;
pub use resolution::{DiscoverySecurity, ResolvedService, resolve_services};
pub use service_type::{ServiceTransport, ServiceType, service_enumeration_name};
pub use txt::{TxtProperty, parse_service_txt};

fn prefixed_name(prefixes: &[&[u8]], domain: &DomainName) -> Result<DomainName, DnsSdError> {
    let mut labels = prefixes
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>();
    labels.extend_from_slice(domain.as_ref());
    DomainName::from_labels(labels).map_err(DnsSdError::InvalidName)
}

#[cfg(test)]
mod tests;

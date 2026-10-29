use super::*;

/// DNS-SD service transport label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceTransport {
    /// `_tcp` service.
    Tcp,
    /// `_udp` service.
    Udp,
}

impl ServiceTransport {
    pub(super) fn label(self) -> &'static [u8] {
        match self {
            Self::Tcp => b"_tcp",
            Self::Udp => b"_udp",
        }
    }
}

/// A DNS-SD service type such as `_http._tcp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceType {
    pub(super) service_label: Vec<u8>,
    pub(super) transport: ServiceTransport,
}

impl ServiceType {
    /// Constructs a service type from an IANA service name without a leading
    /// underscore.
    ///
    /// # Errors
    ///
    /// Returns an error unless the service name is 1–15 ASCII letters,
    /// digits, or hyphens, starts and ends alphanumerically, and contains at
    /// least one letter, with no consecutive hyphens.
    pub fn new(service: &str, transport: ServiceTransport) -> Result<Self, DnsSdError> {
        let bytes = service.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 15
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'-')
            || bytes.windows(2).any(|pair| pair == b"--")
            || !bytes.iter().any(u8::is_ascii_alphabetic)
        {
            return Err(DnsSdError::InvalidServiceType);
        }
        let mut service_label = Vec::with_capacity(bytes.len() + 1);
        service_label.push(b'_');
        service_label.extend(bytes.iter().map(u8::to_ascii_lowercase));
        Ok(Self {
            service_label,
            transport,
        })
    }

    /// Returns the browse owner below `domain`.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting DNS name is too long.
    pub fn owner(&self, domain: &DomainName) -> Result<DomainName, DnsSdError> {
        prefixed_name(
            &[self.service_label.as_slice(), self.transport.label()],
            domain,
        )
    }

    /// Returns a subtype browse owner using the conventional underscore prefix.
    /// An existing leading underscore is preserved. For exact subtype labels,
    /// including labels without an underscore, use `subtype_owner_label`.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting label exceeds 63 bytes or the DNS
    /// name exceeds DNS limits.
    pub fn subtype_owner(
        &self,
        subtype: &str,
        domain: &DomainName,
    ) -> Result<DomainName, DnsSdError> {
        if subtype.is_empty() {
            return Err(DnsSdError::InvalidSubtype);
        }
        if subtype.starts_with('_') {
            self.subtype_owner_label(subtype.as_bytes(), domain)
        } else {
            let mut label = vec![b'_'];
            label.extend_from_slice(subtype.as_bytes());
            self.subtype_owner_label(&label, domain)
        }
    }

    /// Returns a subtype browse owner with the exact supplied label octets.
    /// RFC 6763 permits arbitrary 8-bit data, with no required underscore.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty label, a label longer than 63 octets, or
    /// a DNS name exceeding DNS limits.
    pub fn subtype_owner_label(
        &self,
        subtype: &[u8],
        domain: &DomainName,
    ) -> Result<DomainName, DnsSdError> {
        if subtype.is_empty() || subtype.len() > 63 {
            return Err(DnsSdError::InvalidSubtype);
        }
        prefixed_name(
            &[
                subtype,
                b"_sub",
                self.service_label.as_slice(),
                self.transport.label(),
            ],
            domain,
        )
    }

    /// Constructs the PTR browse question for this service type.
    ///
    /// # Errors
    ///
    /// Returns an error if owner-name construction fails.
    pub fn browse_question(&self, domain: &DomainName) -> Result<Question, DnsSdError> {
        Ok(Question {
            qname: self.owner(domain)?,
            qtype: QueryType::PTR,
            qclass: QClassType::Class(ClassType::IN),
        })
    }
}

/// Returns the service-type enumeration owner
/// `_services._dns-sd._udp.<domain>`.
///
/// # Errors
///
/// Returns an error if the resulting name exceeds DNS limits.
pub fn service_enumeration_name(domain: &DomainName) -> Result<DomainName, DnsSdError> {
    prefixed_name(&[b"_services", b"_dns-sd", b"_udp"], domain)
}

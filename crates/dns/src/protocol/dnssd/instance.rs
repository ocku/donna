use super::*;
use unicode_normalization::{UnicodeNormalization, char::is_public_assigned, is_nfc};

/// A DNS-SD service instance name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstance {
    /// Human-readable instance label octets.
    pub instance_label: Vec<u8>,
    /// Registered service type.
    pub service_type: ServiceType,
    /// Discovery domain.
    pub domain: DomainName,
}

impl ServiceInstance {
    /// Constructs an instance, normalizing its UTF-8 label to NFC.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid UTF-8, forbidden Net-Unicode characters,
    /// or an empty or oversized label after normalization.
    pub fn new(
        instance_label: impl Into<Vec<u8>>,
        service_type: ServiceType,
        domain: DomainName,
    ) -> Result<Self, DnsSdError> {
        let input = instance_label.into();
        let text = std::str::from_utf8(&input).map_err(|_| DnsSdError::InvalidInstanceLabel)?;
        let instance_label = text.nfc().collect::<String>().into_bytes();
        let value = Self {
            instance_label,
            service_type,
            domain,
        };
        value.owner()?;
        Ok(value)
    }

    /// Returns `<Instance>._service._transport.<domain>`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid public-field label data or a name that
    /// exceeds DNS limits. Labels must already be NFC at this boundary.
    pub fn owner(&self) -> Result<DomainName, DnsSdError> {
        validate_instance_label(&self.instance_label)?;
        prefixed_name(
            &[
                self.instance_label.as_slice(),
                self.service_type.service_label.as_slice(),
                self.service_type.transport.label(),
            ],
            &self.domain,
        )
    }

    /// Produces the SRV and TXT questions used to resolve an instance.
    ///
    /// # Errors
    ///
    /// Returns an error if owner-name construction fails.
    pub fn resolve_questions(&self) -> Result<[Question; 2], DnsSdError> {
        let owner = self.owner()?;
        Ok([
            Question {
                qname: owner.clone(),
                qtype: QueryType::SRV,
                qclass: QClassType::Class(ClassType::IN),
            },
            Question {
                qname: owner,
                qtype: QueryType::TXT,
                qclass: QClassType::Class(ClassType::IN),
            },
        ])
    }

    /// Chooses the conventional next label after a duplicate-name conflict.
    ///
    /// # Errors
    ///
    /// Returns an error if the suffix cannot fit in one DNS label.
    pub fn renamed(&self, ordinal: u16) -> Result<Self, DnsSdError> {
        let suffix = format!(" ({})", ordinal.max(2));
        if self.instance_label.len() + suffix.len() > 63 {
            return Err(DnsSdError::InvalidInstanceLabel);
        }
        let mut label = self.instance_label.clone();
        label.extend_from_slice(suffix.as_bytes());
        Self::new(label, self.service_type.clone(), self.domain.clone())
    }
}

fn validate_instance_label(label: &[u8]) -> Result<(), DnsSdError> {
    let text = std::str::from_utf8(label).map_err(|_| DnsSdError::InvalidInstanceLabel)?;
    if label.is_empty()
        || label.len() > 63
        || !is_nfc(text)
        || text.starts_with('\u{feff}')
        || text.chars().any(|character| {
            character.is_control()
                || (!is_public_assigned(character)
                    && !matches!(character, '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{ffffd}' | '\u{100000}'..='\u{10fffd}'))
        })
    {
        return Err(DnsSdError::InvalidInstanceLabel);
    }
    Ok(())
}

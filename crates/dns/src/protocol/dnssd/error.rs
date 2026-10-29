use super::*;

/// Invalid DNS-SD naming, TXT data, or discovery policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsSdError {
    /// Service-type syntax is invalid.
    InvalidServiceType,
    /// Subtype syntax is invalid.
    InvalidSubtype,
    /// Instance label is empty, too long, or invalid Net-Unicode text.
    InvalidInstanceLabel,
    /// TXT key syntax is invalid.
    InvalidTxtKey,
    /// `.local.` data was not marked link-local, or vice versa.
    SecurityModeMismatch,
    /// Unicast discovery data was not DNSSEC secure.
    InsecureUnicastDiscovery,
    /// Constructed DNS name is invalid.
    InvalidName(DomainNameError),
}

impl fmt::Display for DnsSdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceType => formatter.write_str("invalid DNS-SD service type"),
            Self::InvalidSubtype => formatter.write_str("invalid DNS-SD subtype"),
            Self::InvalidInstanceLabel => formatter.write_str("invalid DNS-SD instance label"),
            Self::InvalidTxtKey => formatter.write_str("invalid DNS-SD TXT key"),
            Self::SecurityModeMismatch => formatter.write_str("discovery security mode mismatch"),
            Self::InsecureUnicastDiscovery => {
                formatter.write_str("unicast DNS-SD data is not DNSSEC secure")
            }
            Self::InvalidName(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DnsSdError {}

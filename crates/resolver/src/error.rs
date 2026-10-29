use std::fmt;

use transport::TransportError;

/// Describes a recursive DNS resolution failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResolveError {
    /// The question uses a class or operation that recursive resolution doesn't
    /// support.
    UnsupportedQuestion,
    /// No configured or discovered name server returned a usable response.
    NoReachableServer,
    /// A reachable name server returned a retryable DNS error.
    TemporaryServerFailure,
    /// Resolution exhausted the configured work limit.
    WorkLimitExceeded,
    /// Another operation owns parent-delegation recovery; no remote failure was inferred.
    DelegationRefreshInProgress,
    /// A retained failed-delegation deadline suppresses bootstrap; this cache hit is not renewed.
    CachedDelegationFailure,
    /// A cached NS-address failure prevents repeated upstream work without renewing it.
    CachedNameServerFailure,
    /// The answer contains a CNAME cycle.
    CnameLoop,
    /// A DNSSEC chain was expected but cryptographic validation failed.
    DnssecBogus(dns::DnssecValidationError),
    /// DNSSEC validation could not determine a security state.
    DnssecIndeterminate(dns::DnssecValidationError),
    /// The transport couldn't encode, send, receive, or decode a DNS message.
    Transport(TransportError),
    /// The configured external cache failed, rejected its persisted data or
    /// exhausted bounded transaction conflict retries.
    CacheBackend(std::io::Error),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedQuestion => {
                f.write_str("resolver doesn't support the question class or query type")
            }
            Self::NoReachableServer => f.write_str("no reachable name-server address"),
            Self::TemporaryServerFailure => {
                f.write_str("reachable name servers returned DNS errors")
            }
            Self::WorkLimitExceeded => f.write_str("resolver work limit exceeded"),
            Self::DelegationRefreshInProgress => f.write_str("delegation recovery is in progress"),
            Self::CachedNameServerFailure => f.write_str("cached name-server address failure"),
            Self::CachedDelegationFailure => f.write_str("cached delegation failure"),
            Self::CnameLoop => f.write_str("CNAME alias loop detected"),
            Self::DnssecBogus(error) => write!(f, "DNSSEC validation failed: {error}"),
            Self::DnssecIndeterminate(error) => {
                write!(f, "DNSSEC validation is indeterminate: {error}")
            }
            Self::Transport(error) => error.fmt(f),
            Self::CacheBackend(error) => write!(f, "resolver cache backend failed: {error}"),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::CacheBackend(error) => Some(error),
            Self::DnssecBogus(error) | Self::DnssecIndeterminate(error) => Some(error),
            Self::UnsupportedQuestion
            | Self::NoReachableServer
            | Self::TemporaryServerFailure
            | Self::CachedNameServerFailure
            | Self::CachedDelegationFailure
            | Self::DelegationRefreshInProgress
            | Self::WorkLimitExceeded
            | Self::CnameLoop => None,
        }
    }
}

impl From<TransportError> for ResolveError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

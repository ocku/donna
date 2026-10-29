/// Supported DNS query TYPE values from RFCs 1035, 1995, 2782, 3596, 6844,
/// and 7477.
///
/// `QTYPE` is a superset of `TYPE`, so it includes every resource-record TYPE
/// represented by this crate plus the assigned query-only values below.
///
/// RFC 1035 §3.2.2–§3.2.3, RFC 1995 §2, and RFC 3596 §2.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryType {
    /// Host address (TYPE 1).
    A,
    /// Authoritative name server (TYPE 2).
    NS,
    /// Mail destination (TYPE 3, obsolete).
    MD,
    /// Mail forwarder (TYPE 4, obsolete).
    MF,
    /// Canonical name (TYPE 5).
    CNAME,
    /// Subtree redirection (TYPE 39; RFC 6672).
    DNAME,
    /// Start of authority (TYPE 6).
    SOA,
    /// Mailbox domain name (TYPE 7, experimental).
    MB,
    /// Mail group member (TYPE 8, experimental).
    MG,
    /// Mail rename (TYPE 9, experimental).
    MR,
    /// Null resource record (TYPE 10, experimental).
    NULL,
    /// Well-known services (TYPE 11).
    WKS,
    /// Domain-name pointer (TYPE 12).
    PTR,
    /// Host information (TYPE 13).
    HINFO,
    /// Mailbox or mail-list information (TYPE 14, experimental).
    MINFO,
    /// Mail exchange (TYPE 15).
    MX,
    /// Text strings (TYPE 16).
    TXT,
    /// DNSSEC signature (TYPE 24), including transaction SIG(0).
    SIG,
    /// DNSSEC public key (TYPE 25).
    KEY,
    /// Delegation signer (TYPE 43).
    DS,
    /// DNSSEC RRSet signature (TYPE 46).
    RRSIG,
    /// Next secure owner and type map (TYPE 47).
    NSEC,
    /// DNSSEC public key (TYPE 48).
    DNSKEY,
    /// Hashed authenticated denial of existence (TYPE 50).
    NSEC3,
    /// NSEC3 parameters (TYPE 51).
    NSEC3PARAM,
    /// TLS certificate association (TYPE 52).
    TLSA,
    /// S/MIME certificate association (TYPE 53).
    SMIMEA,
    /// IPv6 host address (TYPE 28).
    AAAA,
    /// Service location (TYPE 33).
    SRV,
    /// Child-to-parent synchronization (TYPE 62).
    CSYNC,
    /// Certification Authority Authorization (TYPE 257).
    CAA,
    /// Request an incremental zone transfer (QTYPE 251).
    IXFR,
    /// Request a transfer of an entire zone (QTYPE 252).
    AXFR,
    /// Request mailbox-related records (QTYPE 253).
    MAILB,
    /// Request mail-agent records (QTYPE 254, obsolete).
    MAILA,
    /// Request all records (QTYPE 255).
    ANY,
    /// An otherwise unassigned QTYPE value retained from the wire.
    Unknown(u16),
}

impl QueryType {
    /// Returns the DNS QTYPE code.
    pub const fn value(self) -> u16 {
        match self {
            Self::A => 1,
            Self::NS => 2,
            Self::MD => 3,
            Self::MF => 4,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::MB => 7,
            Self::MG => 8,
            Self::MR => 9,
            Self::NULL => 10,
            Self::WKS => 11,
            Self::PTR => 12,
            Self::HINFO => 13,
            Self::MINFO => 14,
            Self::MX => 15,
            Self::TXT => 16,
            Self::SIG => 24,
            Self::KEY => 25,
            Self::DS => 43,
            Self::RRSIG => 46,
            Self::NSEC => 47,
            Self::DNSKEY => 48,
            Self::NSEC3 => 50,
            Self::NSEC3PARAM => 51,
            Self::TLSA => 52,
            Self::SMIMEA => 53,
            Self::AAAA => 28,
            Self::SRV => 33,
            Self::DNAME => 39,
            Self::CSYNC => 62,
            Self::CAA => 257,
            Self::IXFR => 251,
            Self::AXFR => 252,
            Self::MAILB => 253,
            Self::MAILA => 254,
            Self::ANY => 255,
            Self::Unknown(value) => value,
        }
    }
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> Self {
        value.value()
    }
}

/// A query-type mnemonic or numeric code that cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryTypeParseError(String);

impl std::fmt::Display for QueryTypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown DNS query type {:?}; use a mnemonic or TYPE<number>",
            self.0
        )
    }
}
impl std::error::Error for QueryTypeParseError {}

macro_rules! query_type_names {
    ($($variant:ident),+ $(,)?) => {
        const QUERY_TYPE_NAMES: &[(&str, QueryType)] = &[
            $((stringify!($variant), QueryType::$variant)),+
        ];

        impl From<u16> for QueryType {
            fn from(code: u16) -> Self {
                $(const $variant: u16 = QueryType::$variant.value();)+
                match code {
                    $($variant => Self::$variant,)+
                    _ => Self::Unknown(code),
                }
            }
        }
    };
}
query_type_names!(
    A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT, SIG, KEY, AAAA,
    SRV, DNAME, DS, RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM, TLSA, SMIMEA, CSYNC, CAA, IXFR, AXFR,
    MAILB, MAILA, ANY,
);

impl std::str::FromStr for QueryType {
    type Err = QueryTypeParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Some((_, value)) = QUERY_TYPE_NAMES
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(text))
        {
            return Ok(*value);
        }
        let uppercase = text.to_ascii_uppercase();
        uppercase
            .strip_prefix("TYPE")
            .unwrap_or(&uppercase)
            .parse::<u16>()
            .ok()
            .filter(|code| *code != 0 && *code != u16::MAX)
            .map(Self::from)
            .ok_or_else(|| QueryTypeParseError(text.to_owned()))
    }
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(code) => write!(f, "TYPE{code}"),
            known => write!(f, "{known:?}"),
        }
    }
}

#[cfg(test)]
mod presentation_tests {
    use super::*;

    #[test]
    fn mnemonics_and_codes_have_one_canonical_representation() {
        for (name, value) in QUERY_TYPE_NAMES {
            assert_eq!(name.parse::<QueryType>().unwrap(), *value);
            assert_eq!(QueryType::from(value.value()), *value);
            assert_eq!(
                format!("TYPE{}", value.value())
                    .parse::<QueryType>()
                    .unwrap(),
                *value
            );
            assert_eq!(value.to_string(), *name);
        }
        assert_eq!("aaaa".parse::<QueryType>().unwrap(), QueryType::AAAA);
        assert_eq!(
            "TYPE65".parse::<QueryType>().unwrap(),
            QueryType::Unknown(65)
        );
        for invalid in ["TYPO", "TYPE65536", "TYPE0", "65535"] {
            assert!(invalid.parse::<QueryType>().is_err());
        }
    }
}

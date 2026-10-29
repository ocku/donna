use super::ClassType;

/// Supported resource-record TYPE codes from RFCs 1034, 1035, 2782, 3596, and
/// 2535, 2931, 6844, 7477, and 8945.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2>
/// RFC 3596: <https://www.rfc-editor.org/rfc/rfc3596#section-2.1>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
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
    /// Opaque data (TYPE 10, experimental).
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
    /// DNSSEC signature, including transaction SIG(0) (TYPE 24).
    SIG,
    /// DNSSEC public key (TYPE 25).
    KEY,
    /// EDNS OPT pseudo-record (TYPE 41).
    OPT,
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
    /// Child-to-parent synchronization (TYPE 62).
    CSYNC,
    /// Transaction Signature meta-record (TYPE 250).
    TSIG,
    /// IPv6 host address (TYPE 28).
    AAAA,
    /// Service location (TYPE 33).
    SRV,
    /// Certification Authority Authorization (TYPE 257).
    CAA,
    /// An RR TYPE code not otherwise represented by this implementation.
    Unknown(u16),
}

/// Converts an RFC 1034/RFC 1035 shared TYPE representation to its wire code.
impl RecordType {
    /// Returns whether `code` has a structured RDATA representation.
    pub(crate) const fn is_known_code(code: u16) -> bool {
        matches!(code, 1..=16 | 24 | 25 | 28 | 33 | 39 | 41 | 43 | 46..=48 | 50..=53 | 62 | 250 | 257)
    }

    /// Returns whether `code` is defined only for the QTYPE field.
    pub(crate) const fn is_query_only_code(code: u16) -> bool {
        matches!(code, 251..=255)
    }

    /// Returns whether `code` is reserved for QTYPE or Meta-TYPE allocation.
    ///
    /// RFC 6895 §3.1 reserves 128–255 for those categories. The assigned
    /// TKEY and TSIG Meta-TYPEs remain representable because they are valid
    /// transient resource records, while the assigned query-only codes do not.
    pub(crate) const fn is_unassigned_query_or_meta_code(code: u16) -> bool {
        matches!(code, 128..=248)
    }

    /// Returns whether this is an RFC 6895 transient Meta-TYPE.
    ///
    /// Meta-TYPEs such as OPT, TKEY, and TSIG carry protocol state and aren't
    /// ordinary resource-record data.
    pub const fn is_meta_type(self) -> bool {
        matches!(self, Self::OPT | Self::TSIG | Self::Unknown(41 | 249))
    }

    /// Returns whether this DNSSEC type may coexist with a CNAME.
    ///
    /// RFC 2181 §10.1 permits SIG, KEY, and NXT; RFC 4035 §2.5 replaces
    /// SIG/NXT with RRSIG/NSEC.
    pub fn is_cname_companion(self) -> bool {
        matches!(
            self,
            Self::SIG | Self::KEY | Self::RRSIG | Self::NSEC | Self::Unknown(30)
        )
    }

    /// Returns whether this implementation has a structured RDATA format for
    /// this TYPE and `class`.
    pub(crate) fn has_standard_rdata_format(self, class: ClassType) -> bool {
        match self {
            Self::A | Self::WKS | Self::AAAA | Self::SRV => class == ClassType::IN,
            Self::OPT => true,
            Self::Unknown(_) => false,
            _ => true,
        }
    }
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        match value {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::SIG => 24,
            RecordType::KEY => 25,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::DNAME => 39,
            RecordType::OPT => 41,
            RecordType::DS => 43,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::TLSA => 52,
            RecordType::SMIMEA => 53,
            RecordType::CSYNC => 62,
            RecordType::TSIG => 250,
            RecordType::CAA => 257,
            RecordType::Unknown(code) => code,
        }
    }
}

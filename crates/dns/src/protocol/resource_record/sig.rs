use crate::DomainName;

/// DNSSEC SIG RDATA, including the RFC 2931 transaction-signature form.
///
/// A transaction SIG(0) has [`Self::type_covered`] set to zero. Ordinary SIG
/// records authenticate the RR TYPE named by that field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sig {
    /// RR TYPE covered by this signature, or zero for SIG(0).
    pub type_covered: u16,
    /// DNSSEC algorithm number.
    pub algorithm: u8,
    /// Number of labels in the original owner name.
    pub labels: u8,
    /// Original TTL of the covered RRSet.
    pub original_ttl: u32,
    /// Latest valid signature time as Unix time modulo 2^32.
    pub signature_expiration: u32,
    /// Earliest valid signature time as Unix time modulo 2^32.
    pub signature_inception: u32,
    /// Key tag identifying the corresponding KEY record.
    pub key_tag: u16,
    /// Owner name of the corresponding KEY record.
    pub signer_name: DomainName,
    /// Algorithm-specific signature octets.
    pub signature: Vec<u8>,
}

impl Sig {
    /// Returns whether this is an RFC 2931 transaction signature.
    pub const fn is_sig0(&self) -> bool {
        self.type_covered == 0
    }
}

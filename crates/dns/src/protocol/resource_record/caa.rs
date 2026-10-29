/// A Certification Authority Authorization property from RFC 6844.
///
/// CAA property values remain octets because each registered property defines
/// its own sub-format. Tag bytes are preserved for record identity; policy
/// helpers compare tags case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Caa {
    /// RFC 6844 flags byte. DNS-numbered bit 0 (`0x80`) is issuer-critical.
    pub flags: u8,
    /// Property tag as US-ASCII octets.
    pub tag: Vec<u8>,
    /// Property value octets.
    pub value: Vec<u8>,
}

pub(crate) fn is_valid_caa_property_tag(tag: &[u8]) -> bool {
    !tag.is_empty() && tag.iter().all(u8::is_ascii_alphanumeric)
}

impl Caa {
    /// Issuer-critical flag mask.
    ///
    /// RFC 1035 numbers the most-significant bit as bit zero, so the flag's
    /// numeric value is 128 rather than 1.
    pub const ISSUER_CRITICAL_FLAG: u8 = 0x80;

    /// Returns whether the issuer-critical flag is asserted.
    #[must_use]
    pub const fn is_issuer_critical(&self) -> bool {
        self.flags & Self::ISSUER_CRITICAL_FLAG != 0
    }

    /// Returns whether flags reserved by RFC 6844 are present.
    ///
    /// Receivers must ignore these bits. New records produced under RFC 6844
    /// must clear them, which master-file and zone publication validation
    /// enforce. Generic record validation preserves received values so caches
    /// and forwarders do not rewrite data covered by DNSSEC signatures.
    #[must_use]
    pub const fn has_reserved_flags(&self) -> bool {
        self.flags & !Self::ISSUER_CRITICAL_FLAG != 0
    }

    /// Compares this property tag with an ASCII tag, ignoring ASCII case.
    #[must_use]
    pub fn tag_eq(&self, tag: &[u8]) -> bool {
        self.tag.eq_ignore_ascii_case(tag)
    }

    /// Returns whether this RFC defines the property's interpretation.
    ///
    /// The defined properties are `issue`, `issuewild`, and `iodef`. The
    /// `auth`, `path`, and `policy` registry entries are reserved rather than
    /// defined by RFC 6844.
    #[must_use]
    pub fn has_standard_tag(&self) -> bool {
        self.tag_eq(b"issue") || self.tag_eq(b"issuewild") || self.tag_eq(b"iodef")
    }

    /// Selects the authorization entries applicable to an issuance request.
    ///
    /// For an ordinary domain, only `issue` applies. For a wildcard domain,
    /// any `issuewild` entry makes all `issue` entries in the RRSet
    /// inapplicable; without `issuewild`, `issue` remains applicable.
    pub fn applicable_issue_properties(
        records: &[Self],
        wildcard: bool,
    ) -> impl Iterator<Item = &Self> {
        let use_issuewild = wildcard && records.iter().any(|record| record.tag_eq(b"issuewild"));
        records.iter().filter(move |record| {
            if use_issuewild {
                record.tag_eq(b"issuewild")
            } else {
                record.tag_eq(b"issue")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Caa;

    fn property(flags: u8, tag: &[u8]) -> Caa {
        Caa {
            flags,
            tag: tag.to_vec(),
            value: Vec::new(),
        }
    }

    #[test]
    fn preserves_exact_identity_while_interpreting_tags_case_insensitively() {
        let issue = property(0x80, b"IsSuE");
        assert!(issue.is_issuer_critical());
        assert!(!issue.has_reserved_flags());
        assert!(issue.tag_eq(b"issue"));
        assert!(issue.has_standard_tag());

        let future = property(0x81, b"future");
        assert!(future.is_issuer_critical());
        assert!(future.has_reserved_flags());
        assert!(!future.has_standard_tag());

        assert_ne!(issue, property(0x80, b"iSsUe"));
        assert_ne!(issue, property(0, b"IsSuE"));
        assert_ne!(
            issue,
            Caa {
                value: vec![1],
                ..property(0x80, b"IsSuE")
            }
        );
    }

    #[test]
    fn issuewild_takes_precedence_only_for_wildcards() {
        let records = vec![
            property(0, b"issue"),
            property(0, b"iodef"),
            property(0, b"ISSUEWILD"),
            property(0, b"issue"),
        ];

        let ordinary = Caa::applicable_issue_properties(&records, false).collect::<Vec<_>>();
        assert_eq!(ordinary.len(), 2);
        assert!(ordinary.iter().all(|entry| entry.tag_eq(b"issue")));

        let wildcard = Caa::applicable_issue_properties(&records, true).collect::<Vec<_>>();
        assert_eq!(wildcard.len(), 1);
        assert!(wildcard[0].tag_eq(b"issuewild"));

        let without_issuewild = &records[..2];
        assert_eq!(
            Caa::applicable_issue_properties(without_issuewild, true).count(),
            1
        );
    }
}

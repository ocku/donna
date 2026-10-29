use super::*;

/// NSEC RDATA linking canonical zone owners and listing present RR types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec {
    /// Next authoritative owner in canonical DNSSEC name order.
    pub next_domain_name: DomainName,
    /// RR TYPEs present at the NSEC owner.
    pub type_bitmap: TypeBitmap,
}

impl Nsec {
    /// Tests whether this NSEC interval covers `name` in canonical DNSSEC
    /// order.
    ///
    /// Both endpoints are excluded. An NSEC whose next name equals its owner
    /// covers every other canonical name.
    pub fn covers_name(&self, owner: &DomainName, name: &DomainName) -> bool {
        let owner_to_next = owner.canonical_cmp(&self.next_domain_name);
        if owner_to_next == Ordering::Equal {
            return !owner.eq_dns(name);
        }
        let owner_to_name = owner.canonical_cmp(name);
        let name_to_next = name.canonical_cmp(&self.next_domain_name);
        if owner_to_next == Ordering::Less {
            owner_to_name == Ordering::Less && name_to_next == Ordering::Less
        } else {
            owner_to_name == Ordering::Less || name_to_next == Ordering::Less
        }
    }

    /// Tests whether a matching NSEC bitmap proves that `qtype` and CNAME are
    /// both absent.
    pub fn proves_nodata(&self, qtype: u16) -> bool {
        !self.type_bitmap.contains(qtype)
            && !self
                .type_bitmap
                .contains(u16::from(crate::RecordType::CNAME))
    }
}

/// NSEC3 RDATA linking hashed owners and listing present RR types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec3 {
    /// Hash algorithm; RFC 5155 defines value 1 as SHA-1.
    pub hash_algorithm: u8,
    /// NSEC3 flags, including the Opt-Out flag.
    pub flags: u8,
    /// Additional hash iterations after the initial digest.
    pub iterations: u16,
    /// Salt octets, or an empty vector for no salt.
    pub salt: Vec<u8>,
    /// Raw binary hash of the next NSEC3 owner.
    pub next_hashed_owner_name: Vec<u8>,
    /// RR TYPEs present at the original owner, or no map for an empty
    /// non-terminal.
    pub type_bitmap: Option<TypeBitmap>,
}

impl Nsec3 {
    /// RFC 5155's Opt-Out flag.
    pub const OPT_OUT_FLAG: u8 = 0x01;

    /// Returns whether the Opt-Out flag is set.
    pub const fn opt_out(&self) -> bool {
        self.flags & Self::OPT_OUT_FLAG != 0
    }

    /// Hashes `name` using this record's algorithm, salt, and iterations.
    ///
    /// `maximum_iterations` is a caller-selected resource-exhaustion bound.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported hash algorithm, a salt longer than
    /// 255 octets, or an iteration count exceeding the supplied bound.
    pub fn hash_name(
        &self,
        name: &DomainName,
        maximum_iterations: u16,
    ) -> Result<Vec<u8>, Nsec3HashError> {
        nsec3_hash(
            name,
            self.hash_algorithm,
            self.iterations,
            &self.salt,
            maximum_iterations,
        )
    }

    /// Hashes `name` into fixed-size SHA-1 storage without temporary allocations.
    ///
    /// Applies the same algorithm and caller-selected iteration bounds as
    /// [`Self::hash_name`], preserving its canonicalization and error precedence.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::hash_name`].
    pub fn hash_name_fixed(
        &self,
        name: &DomainName,
        maximum_iterations: u16,
    ) -> Result<[u8; 20], Nsec3HashError> {
        nsec3_hash_fixed(
            name,
            self.hash_algorithm,
            self.iterations,
            &self.salt,
            maximum_iterations,
        )
    }

    /// Returns the lowercase unpadded Base32hex owner label for `name`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::hash_name`].
    pub fn hash_name_label(
        &self,
        name: &DomainName,
        maximum_iterations: u16,
    ) -> Result<String, Nsec3HashError> {
        self.hash_name(name, maximum_iterations)
            .map(|hash| base32hex(&hash))
    }

    /// Tests whether an NSEC3 owner represents `name` in `zone`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid owner structure/Base32hex or a hash
    /// calculation that exceeds the caller's policy.
    pub fn matches_name(
        &self,
        nsec3_owner: &DomainName,
        zone: &DomainName,
        name: &DomainName,
        maximum_iterations: u16,
    ) -> Result<bool, Nsec3ProofError> {
        let owner_hash = nsec3_owner_hash(nsec3_owner, zone)?;
        Ok(owner_hash == self.hash_name(name, maximum_iterations)?)
    }

    /// Tests whether this NSEC3 interval covers the hash of `name`.
    ///
    /// Interval endpoints are excluded; a one-record chain covers every hash
    /// except its own owner hash.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed proof data or bounded hash failure.
    pub fn covers_name(
        &self,
        nsec3_owner: &DomainName,
        zone: &DomainName,
        name: &DomainName,
        maximum_iterations: u16,
    ) -> Result<bool, Nsec3ProofError> {
        let owner_hash = nsec3_owner_hash(nsec3_owner, zone)?;
        if owner_hash.len() != self.next_hashed_owner_name.len() {
            return Err(Nsec3ProofError::HashLengthMismatch);
        }
        let target = self.hash_name(name, maximum_iterations)?;
        if owner_hash == self.next_hashed_owner_name {
            return Ok(target != owner_hash);
        }
        if owner_hash < self.next_hashed_owner_name {
            Ok(owner_hash < target && target < self.next_hashed_owner_name)
        } else {
            Ok(target > owner_hash || target < self.next_hashed_owner_name)
        }
    }
}

/// NSEC3PARAM RDATA describing a zone's NSEC3 chain parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec3param {
    /// Hash algorithm; RFC 5155 defines value 1 as SHA-1.
    pub hash_algorithm: u8,
    /// Flags field, which must be zero when authored.
    pub flags: u8,
    /// Additional hash iterations after the initial digest.
    pub iterations: u16,
    /// Salt octets, or an empty vector for no salt.
    pub salt: Vec<u8>,
}

impl Nsec3param {
    /// Hashes `name` using these zone parameters.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported hash algorithm, a salt longer than
    /// 255 octets, or an iteration count exceeding `maximum_iterations`.
    pub fn hash_name(
        &self,
        name: &DomainName,
        maximum_iterations: u16,
    ) -> Result<Vec<u8>, Nsec3HashError> {
        nsec3_hash(
            name,
            self.hash_algorithm,
            self.iterations,
            &self.salt,
            maximum_iterations,
        )
    }

    /// Hashes `name` into fixed-size SHA-1 storage without temporary allocations.
    ///
    /// Applies the same algorithm and caller-selected iteration bounds as
    /// [`Self::hash_name`], preserving its canonicalization and error precedence.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::hash_name`].
    pub fn hash_name_fixed(
        &self,
        name: &DomainName,
        maximum_iterations: u16,
    ) -> Result<[u8; 20], Nsec3HashError> {
        nsec3_hash_fixed(
            name,
            self.hash_algorithm,
            self.iterations,
            &self.salt,
            maximum_iterations,
        )
    }

    /// Hashes each suffix of a validated name, starting with the full name and
    /// ending with the root, without constructing temporary domain names.
    ///
    /// Each result applies the same algorithm, canonicalization, salt and
    /// iteration bound as [`Self::hash_name_fixed`].
    pub fn hash_name_suffixes_fixed<'a>(
        &'a self,
        name: &'a DomainName,
        maximum_iterations: u16,
    ) -> impl Iterator<Item = Result<[u8; 20], Nsec3HashError>> + 'a {
        (0..=name.as_ref().len()).map(move |dropped| {
            nsec3_hash_labels_fixed(
                &name.as_ref()[dropped..],
                self.hash_algorithm,
                self.iterations,
                &self.salt,
                maximum_iterations,
            )
        })
    }

    /// Returns the lowercase unpadded Base32hex owner label for `name`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::hash_name`].
    pub fn hash_name_label(
        &self,
        name: &DomainName,
        maximum_iterations: u16,
    ) -> Result<String, Nsec3HashError> {
        self.hash_name(name, maximum_iterations)
            .map(|hash| base32hex(&hash))
    }
}

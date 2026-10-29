use super::*;

/// A generated RFC 5155 NSEC3 chain and its apex NSEC3PARAM record.
#[derive(Debug, Clone)]
pub struct Nsec3Chain {
    pub(super) parameters: ResourceRecord,
    pub(super) records: Vec<ResourceRecord>,
}

impl Nsec3Chain {
    /// Builds a complete NSEC3 chain from authoritative zone records.
    ///
    /// Empty non-terminals are included with empty type bitmaps. In Opt-Out
    /// mode, unsigned delegations and non-authoritative names below every
    /// delegation are omitted. The generated type bitmaps include RRSIG and
    /// the apex NSEC3PARAM type, but never NSEC3 itself.
    ///
    /// # Errors
    ///
    /// Returns an error for records outside the zone or class, invalid
    /// parameters, excessive hash work, owner-name overflow, or a hash
    /// collision.
    pub fn build(
        zone: &DomainName,
        class: ClassType,
        source_records: &[ResourceRecord],
        parameters: Nsec3param,
        ttl: u32,
        opt_out: bool,
        maximum_iterations: u16,
    ) -> Result<Self, Nsec3ChainError> {
        if parameters.flags != 0 || parameters.salt.len() > usize::from(u8::MAX) {
            return Err(Nsec3ChainError::InvalidParameters);
        }
        parameters
            .hash_name(zone, maximum_iterations)
            .map_err(Nsec3ChainError::Hash)?;

        let mut delegations = HashMap::<DomainName, bool>::new();
        for record in source_records {
            if record.class != class || !record.name.is_descendant_of(zone) {
                return Err(Nsec3ChainError::RecordOutsideZone);
            }
            if record.rtype == RecordType::NS && !record.name.eq_dns(zone) {
                delegations.entry(record.name.clone()).or_insert(false);
            }
            if record.rtype == RecordType::DS {
                delegations.insert(record.name.clone(), true);
            }
        }

        let below_delegation = |name: &DomainName| {
            delegations
                .keys()
                .any(|delegation| !name.eq_dns(delegation) && name.is_descendant_of(delegation))
        };
        let mut owner_types = HashMap::<DomainName, BTreeSet<u16>>::new();
        for record in source_records {
            if below_delegation(&record.name)
                || matches!(record.rtype, RecordType::NSEC3 | RecordType::NSEC3PARAM)
            {
                continue;
            }
            if opt_out && delegations.get(&record.name).is_some_and(|has_ds| !has_ds) {
                continue;
            }
            owner_types
                .entry(record.name.clone())
                .or_default()
                .insert(u16::from(record.rtype));
        }
        let apex_types = owner_types
            .get_mut(zone)
            .ok_or(Nsec3ChainError::MissingApex)?;
        apex_types.insert(u16::from(RecordType::NSEC3PARAM));
        for types in owner_types.values_mut() {
            types.insert(u16::from(RecordType::RRSIG));
            types.remove(&u16::from(RecordType::NSEC3));
        }

        let existing_owners = owner_types.keys().cloned().collect::<Vec<_>>();
        for owner in existing_owners {
            let labels = owner.as_ref();
            let zone_labels = zone.as_ref().len();
            for first_label in 1..labels.len() - zone_labels {
                let ancestor = DomainName::from_labels(labels[first_label..].to_vec())
                    .expect("a suffix of a valid domain name is valid");
                if !below_delegation(&ancestor) {
                    owner_types.entry(ancestor).or_default();
                }
            }
        }

        let mut hashed = Vec::with_capacity(owner_types.len());
        let mut hashes = HashMap::<Vec<u8>, DomainName>::new();
        for (owner, types) in owner_types {
            let hash = parameters
                .hash_name(&owner, maximum_iterations)
                .map_err(Nsec3ChainError::Hash)?;
            if let Some(previous) = hashes.insert(hash.clone(), owner.clone())
                && !previous.eq_dns(&owner)
            {
                return Err(Nsec3ChainError::HashCollision {
                    first: previous,
                    second: owner,
                });
            }
            let bitmap = if types.is_empty() {
                None
            } else {
                Some(TypeBitmap::new(types).map_err(Nsec3ChainError::TypeBitmap)?)
            };
            hashed.push((hash, bitmap));
        }
        hashed.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        if hashed.is_empty() {
            return Err(Nsec3ChainError::MissingApex);
        }

        let mut records = Vec::with_capacity(hashed.len());
        for index in 0..hashed.len() {
            let (hash, bitmap) = &hashed[index];
            let next_hash = hashed[(index + 1) % hashed.len()].0.clone();
            let mut owner_labels = Vec::with_capacity(zone.as_ref().len() + 1);
            owner_labels.push(base32hex(hash).into_bytes());
            owner_labels.extend_from_slice(zone.as_ref());
            let owner =
                DomainName::from_labels(owner_labels).map_err(Nsec3ChainError::OwnerName)?;
            records.push(ResourceRecord {
                name: owner,
                rtype: RecordType::NSEC3,
                class,
                ttl,
                rdata: RData::NSEC3(Nsec3 {
                    hash_algorithm: parameters.hash_algorithm,
                    flags: if opt_out { Nsec3::OPT_OUT_FLAG } else { 0 },
                    iterations: parameters.iterations,
                    salt: parameters.salt.clone(),
                    next_hashed_owner_name: next_hash,
                    type_bitmap: bitmap.clone(),
                }),
            });
        }
        let parameter_record = ResourceRecord {
            name: zone.clone(),
            rtype: RecordType::NSEC3PARAM,
            class,
            ttl,
            rdata: RData::NSEC3PARAM(parameters),
        };
        parameter_record
            .validate()
            .map_err(Nsec3ChainError::InvalidRecord)?;
        for record in &records {
            record.validate().map_err(Nsec3ChainError::InvalidRecord)?;
        }
        Ok(Self {
            parameters: parameter_record,
            records,
        })
    }

    /// Returns the apex NSEC3PARAM record for this chain.
    pub const fn parameters(&self) -> &ResourceRecord {
        &self.parameters
    }

    /// Returns the NSEC3 records in raw hash order.
    pub fn records(&self) -> &[ResourceRecord] {
        &self.records
    }

    /// Consumes the chain into the apex parameter record and ordered NSEC3
    /// records.
    pub fn into_records(self) -> (ResourceRecord, Vec<ResourceRecord>) {
        (self.parameters, self.records)
    }
}

/// An NSEC3 chain-construction failure.
#[derive(Debug)]
pub enum Nsec3ChainError {
    /// NSEC3PARAM flags, salt, or hash algorithm cannot be authored.
    InvalidParameters,
    /// A source record is outside the requested zone or class.
    RecordOutsideZone,
    /// The source zone does not contain an apex owner.
    MissingApex,
    /// Hashing is unsupported or exceeds the configured iteration bound.
    Hash(Nsec3HashError),
    /// Two distinct original owner names produced the same NSEC3 hash.
    HashCollision {
        /// First colliding original owner.
        first: DomainName,
        /// Second colliding original owner.
        second: DomainName,
    },
    /// A generated hashed owner name exceeds DNS wire limits.
    OwnerName(DomainNameError),
    /// A generated type bitmap is invalid.
    TypeBitmap(TypeBitmapError),
    /// A generated NSEC3 or NSEC3PARAM record violates DNS wire semantics.
    InvalidRecord(RecordValidationError),
}

impl fmt::Display for Nsec3ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameters => formatter.write_str("invalid NSEC3 chain parameters"),
            Self::RecordOutsideZone => {
                formatter.write_str("source record is outside the NSEC3 zone or class")
            }
            Self::MissingApex => formatter.write_str("NSEC3 source zone has no apex records"),
            Self::Hash(error) => write!(formatter, "NSEC3 hashing failed: {error}"),
            Self::HashCollision { first, second } => write!(
                formatter,
                "NSEC3 hash collision between {first:?} and {second:?}"
            ),
            Self::OwnerName(error) => write!(formatter, "invalid NSEC3 owner name: {error}"),
            Self::TypeBitmap(error) => write!(formatter, "invalid NSEC3 type bitmap: {error}"),
            Self::InvalidRecord(error) => {
                write!(formatter, "invalid generated NSEC3 record: {error}")
            }
        }
    }
}

impl std::error::Error for Nsec3ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Hash(error) => Some(error),
            Self::OwnerName(error) => Some(error),
            Self::TypeBitmap(error) => Some(error),
            Self::InvalidRecord(error) => Some(error),
            _ => None,
        }
    }
}

/// An NSEC3 name-hash failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nsec3HashError {
    /// Only RFC 5155 SHA-1 algorithm 1 is implemented.
    UnsupportedAlgorithm {
        /// Rejected NSEC3 hash algorithm.
        algorithm: u8,
    },
    /// The advertised iteration count exceeds the caller's work bound.
    TooManyIterations {
        /// Advertised iteration count.
        iterations: u16,
        /// Caller-selected limit.
        maximum: u16,
    },
    /// The salt exceeds its one-octet wire length field.
    SaltTooLong {
        /// Rejected salt length in octets.
        length: usize,
    },
}

impl fmt::Display for Nsec3HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(formatter, "unsupported NSEC3 hash algorithm {algorithm}")
            }
            Self::TooManyIterations {
                iterations,
                maximum,
            } => write!(
                formatter,
                "NSEC3 iteration count {iterations} exceeds limit {maximum}"
            ),
            Self::SaltTooLong { length } => {
                write!(formatter, "NSEC3 salt length {length} exceeds {}", u8::MAX)
            }
        }
    }
}

impl std::error::Error for Nsec3HashError {}

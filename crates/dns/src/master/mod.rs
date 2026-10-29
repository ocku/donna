//! RFC 1035 master-file (zone-file) loading with RFC 2782 SRV, RFC 3596 AAAA,
//! RFC 3597 generic-record, RFC 6844 CAA, and RFC 7477 CSYNC support.
//!
//! The loader resolves master-file presentation data into the protocol-layer
//! `ResourceRecord` representation.  It implements RFC 1035 §5.1's origin,
//! owner, class, and TTL state, including `$INCLUDE` for path-based loads and
//! RFC 2308 §4's `$TTL` default-TTL directive.

mod lexer;
mod presentation;
mod rdata;
mod record;
mod state;
mod wks;

use std::{fmt, fs, path::Path};

use crate::protocol::{
    DomainName, DomainNameError, RecordValidationError, ResourceRecord, validate_zone_records,
};

use state::{State, parse_entries};

#[cfg(test)]
use crate::constants::MAX_TTL;
#[cfg(test)]
use crate::protocol::{ClassType, RData, RecordType};
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};

/// A master file translated to DNS protocol resource records.
#[derive(Debug, Clone)]
pub struct MasterFile {
    /// Contains the resource records in source order.
    pub records: Vec<ResourceRecord>,
}

/// An error that prevents a master file from defining a zone.
#[derive(Debug)]
pub struct MasterError {
    message: String,
}

impl MasterError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MasterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for MasterError {}
impl From<DomainNameError> for MasterError {
    fn from(error: DomainNameError) -> Self {
        Self::new(error.to_string())
    }
}

impl MasterFile {
    /// Parses an in-memory master file. Relative names require `origin`.
    ///
    /// `$INCLUDE` needs a filesystem base directory; use [`Self::from_path`]
    /// for a master file that contains include directives.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is malformed, omits required inherited
    /// state, or contains an `$INCLUDE` directive.
    pub fn parse(input: &str, origin: Option<DomainName>) -> Result<Self, MasterError> {
        let mut records = Vec::new();
        let mut state = State {
            origin,
            owner: None,
            class: None,
            default_ttl: None,
            last_explicit_ttl: None,
            base: None,
            include_stack: Vec::new(),
        };
        parse_entries(input, &mut state, &mut records)?;
        Ok(Self { records })
    }

    /// Strictly validates the record-set and CNAME invariants of this zone data.
    ///
    /// Parsing stays permissive so callers can inspect invalid input, while
    /// servers can require this check before loading records for service.
    ///
    /// # Errors
    ///
    /// Returns an error if a record or RRSet violates DNS zone-data rules.
    pub fn validate_strict(&self) -> Result<(), RecordValidationError> {
        validate_zone_records(&self.records)
    }

    /// Loads a master file and recursively processes RFC 1035 `$INCLUDE`
    /// directives. Relative include filenames are relative to their including
    /// file.
    ///
    /// # Errors
    ///
    /// Returns an error if a file cannot be resolved or read, an include cycle
    /// or depth limit is detected, or any loaded input is malformed.
    pub fn from_path(
        path: impl AsRef<Path>,
        origin: Option<DomainName>,
    ) -> Result<Self, MasterError> {
        let path = path.as_ref();
        let path = fs::canonicalize(path).map_err(|error| {
            MasterError::new(format!("cannot resolve {}: {error}", path.display()))
        })?;
        let input = fs::read_to_string(&path).map_err(|error| {
            MasterError::new(format!("cannot read {}: {error}", path.display()))
        })?;
        let mut records = Vec::new();
        let mut state = State {
            origin,
            owner: None,
            class: None,
            default_ttl: None,
            last_explicit_ttl: None,
            base: path.parent().map(Path::to_path_buf),
            include_stack: vec![path],
        };
        parse_entries(&input, &mut state, &mut records)?;
        Ok(Self { records })
    }
}

#[cfg(test)]
mod tests;

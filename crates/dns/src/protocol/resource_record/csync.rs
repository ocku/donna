use std::{collections::BTreeSet, fmt, sync::Arc};

/// An RFC 4034 canonical DNS type bitmap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeBitmap {
    codes: Arc<[u16]>,
    // Immutable shared storage keeps cloning signed proof records cheap.
    // Preserve ignored received bits because they remain covered by RRSIGs.
    wire_codes: Arc<[u16]>,
}

impl TypeBitmap {
    /// Creates a sorted, duplicate-free bitmap from ordinary RR TYPE codes.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty set, TYPE zero, or a query/meta type.
    pub fn new(codes: impl IntoIterator<Item = u16>) -> Result<Self, TypeBitmapError> {
        let codes = codes.into_iter().collect::<BTreeSet<_>>();
        if codes.is_empty() {
            return Err(TypeBitmapError::Empty);
        }
        if codes.contains(&0) {
            return Err(TypeBitmapError::ReservedType { value: 0 });
        }
        if let Some(&value) = codes.iter().find(|&&code| is_pseudo_type(code)) {
            return Err(TypeBitmapError::PseudoType { value });
        }
        let codes = codes.into_iter().collect::<Arc<[u16]>>();
        Ok(Self {
            wire_codes: codes.clone(),
            codes,
        })
    }

    pub(crate) fn from_received_codes(codes: BTreeSet<u16>) -> Result<Self, TypeBitmapError> {
        if codes.is_empty() {
            return Err(TypeBitmapError::Empty);
        }
        if codes.contains(&0) {
            return Err(TypeBitmapError::ReservedType { value: 0 });
        }
        let has_ignored_codes = codes.iter().any(|&code| is_pseudo_type(code));
        let wire_codes = codes.into_iter().collect::<Arc<[u16]>>();
        let codes = if has_ignored_codes {
            wire_codes
                .iter()
                .copied()
                .filter(|&code| !is_pseudo_type(code))
                .collect()
        } else {
            Arc::clone(&wire_codes)
        };
        Ok(Self { codes, wire_codes })
    }

    /// Returns ascending ordinary TYPE codes, excluding received pseudo-type bits.
    pub fn codes(&self) -> &[u16] {
        &self.codes
    }

    /// Returns whether the bitmap semantically contains the ordinary TYPE `code`.
    pub fn contains(&self, code: u16) -> bool {
        self.codes.binary_search(&code).is_ok()
    }

    pub(crate) fn wire_codes(&self) -> &[u16] {
        &self.wire_codes
    }

    pub(crate) fn wire_len(&self) -> usize {
        let mut length = 0;
        let mut window = None;
        let mut largest_low = 0_u8;
        for &code in self.wire_codes.iter() {
            let code_window = (code >> 8) as u8;
            let low = code as u8;
            if window != Some(code_window) {
                if window.is_some() {
                    length += 2 + usize::from(largest_low / 8) + 1;
                }
                window = Some(code_window);
                largest_low = low;
            } else {
                largest_low = low;
            }
        }
        if window.is_some() {
            length += 2 + usize::from(largest_low / 8) + 1;
        }
        length
    }
}

fn is_pseudo_type(code: u16) -> bool {
    matches!(code, 41 | 128..=255)
}

/// A type bitmap cannot be represented as ordinary zone-data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeBitmapError {
    /// No RR TYPE bit was supplied.
    Empty,
    /// TYPE zero is reserved.
    ReservedType {
        /// Contains the rejected TYPE code.
        value: u16,
    },
    /// Query-only and transient meta types cannot occur in zone type maps.
    PseudoType {
        /// Contains the rejected TYPE code.
        value: u16,
    },
}

impl fmt::Display for TypeBitmapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("a type bitmap must contain at least one RR TYPE"),
            Self::ReservedType { value } => write!(formatter, "TYPE {value} is reserved"),
            Self::PseudoType { value } => {
                write!(
                    formatter,
                    "pseudo-TYPE {value} cannot appear in a type bitmap"
                )
            }
        }
    }
}

impl std::error::Error for TypeBitmapError {}

/// Child-to-parent synchronization signaling data.
///
/// RFC 7477 section 2.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Csync {
    /// Child SOA serial associated with the requested delegation data.
    pub soa_serial: u32,
    /// RFC 7477 CSYNC flags, including any received future flag bits.
    pub flags: u16,
    /// RR TYPEs requested for atomic parental processing.
    pub type_bitmap: TypeBitmap,
}

impl Csync {
    /// Requests immediate processing when permitted by parental policy.
    pub const IMMEDIATE_FLAG: u16 = 0x0001;
    /// Requires the child SOA serial not to precede [`Self::soa_serial`].
    pub const SOA_MINIMUM_FLAG: u16 = 0x0002;
    /// All flags defined by RFC 7477.
    pub const KNOWN_FLAGS: u16 = Self::IMMEDIATE_FLAG | Self::SOA_MINIMUM_FLAG;

    /// Returns whether immediate processing was requested.
    pub const fn immediate(&self) -> bool {
        self.flags & Self::IMMEDIATE_FLAG != 0
    }

    /// Returns whether the SOA minimum serial requirement is active.
    pub const fn soa_minimum(&self) -> bool {
        self.flags & Self::SOA_MINIMUM_FLAG != 0
    }

    /// Returns received flag bits not defined by RFC 7477.
    pub const fn unknown_flags(&self) -> u16 {
        self.flags & !Self::KNOWN_FLAGS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_bitmap_constructor_sorts_deduplicates_and_rejects_non_data_types() {
        assert_eq!(TypeBitmap::new([28, 1, 2, 1]).unwrap().codes(), &[1, 2, 28]);
        assert_eq!(TypeBitmap::new([]), Err(TypeBitmapError::Empty));
        assert_eq!(
            TypeBitmap::new([0]),
            Err(TypeBitmapError::ReservedType { value: 0 })
        );
        for value in [41, 128, 249, 255] {
            assert_eq!(
                TypeBitmap::new([value]),
                Err(TypeBitmapError::PseudoType { value })
            );
        }
    }
}

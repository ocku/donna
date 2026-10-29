use std::hash::{Hash, Hasher};
use std::{cmp::Ordering, fmt, sync::Arc};

use crate::constants::{MAX_LABEL_OCTETS, MAX_NAME_OCTETS};

/// A DNS domain name represented as uncompressed raw label octets.
///
/// The root domain is represented by an empty label list. Message-compression
/// pointers are a wire-format concern and are intentionally not retained here.
/// Labels are immutable and shared between clones, including cached records.
///
/// RFC 1035 §§2.3.3–2.3.4 and §3.1.
#[derive(Clone)]
pub struct DomainName(Option<Arc<Vec<Vec<u8>>>>);

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DomainName").field(&self.as_ref()).finish()
    }
}

impl PartialEq for DomainName {
    fn eq(&self, other: &Self) -> bool {
        self.eq_dns(other)
    }
}

impl Eq for DomainName {}

impl Hash for DomainName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // The canonical wire spelling preserves label boundaries and binary
        // octets. Feeding it in one slice keeps randomized hashing while
        // avoiding a separate hasher call for every label and length.
        let mut folded = [0; MAX_NAME_OCTETS];
        let mut end = 0;
        for label in self.as_ref() {
            folded[end] = label.len() as u8;
            end += 1;
            for (target, octet) in folded[end..end + label.len()].iter_mut().zip(label) {
                *target = octet.to_ascii_lowercase();
            }
            end += label.len();
        }
        folded[..end + 1].hash(state);
    }
}

/// A domain name that cannot be represented by RFC 1035's wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainNameError {
    /// Only the terminating root label may be empty.
    EmptyLabel {
        /// Identifies the zero-based invalid label.
        index: usize,
    },
    /// A label exceeds the six-bit RFC 1035 label length field.
    LabelTooLong {
        /// Identifies the zero-based invalid label.
        index: usize,
        /// Reports the label length in octets.
        length: usize,
    },
    /// The name, including all label-length octets and the root label, exceeds
    /// the RFC 1035 wire limit.
    NameTooLong {
        /// Reports the uncompressed wire length in octets.
        length: usize,
    },
}

impl fmt::Display for DomainNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLabel { index } => write!(f, "DNS label {index} is empty"),
            Self::LabelTooLong { index, length } => {
                write!(
                    f,
                    "DNS label {index} is {length} octets; maximum is {MAX_LABEL_OCTETS}"
                )
            }
            Self::NameTooLong { length } => {
                write!(
                    f,
                    "DNS name is {length} wire octets; maximum is {MAX_NAME_OCTETS}"
                )
            }
        }
    }
}

impl std::error::Error for DomainNameError {}

impl DomainName {
    /// Parses a dot-separated domain name, accepting an optional trailing root dot.
    ///
    /// This convenience syntax does not interpret master-file escape sequences;
    /// use [`Self::from_labels`] when labels contain arbitrary octets.
    ///
    /// # Errors
    ///
    /// Returns an error if the name contains an empty or oversized label, or
    /// exceeds the DNS wire-length limit.
    pub fn from_dotted(name: &str) -> Result<Self, DomainNameError> {
        if name == "." {
            return Ok(Self::root());
        }

        let name = name.strip_suffix('.').unwrap_or(name);
        Self::from_labels(
            name.split('.')
                .map(|label| label.as_bytes().to_vec())
                .collect(),
        )
    }

    /// Constructs a domain name from raw DNS label octets.
    ///
    /// # Errors
    ///
    /// Returns an error if any label is empty or oversized, or if the complete
    /// name exceeds the DNS wire-length limit.
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Self, DomainNameError> {
        let mut wire_length = 1; // terminating root label
        for (index, label) in labels.iter().enumerate() {
            if label.is_empty() {
                return Err(DomainNameError::EmptyLabel { index });
            }
            if label.len() > usize::from(MAX_LABEL_OCTETS) {
                return Err(DomainNameError::LabelTooLong {
                    index,
                    length: label.len(),
                });
            }
            wire_length += 1 + label.len();
        }

        if wire_length > MAX_NAME_OCTETS {
            return Err(DomainNameError::NameTooLong {
                length: wire_length,
            });
        }

        Ok(if labels.is_empty() {
            Self::root()
        } else {
            Self(Some(Arc::new(labels)))
        })
    }

    /// Returns the root domain.
    pub const fn root() -> Self {
        Self(None)
    }

    /// Returns this name's length in RFC 1035 uncompressed wire format.
    pub fn wire_len(&self) -> usize {
        self.as_ref()
            .iter()
            .map(|label| 1 + label.len())
            .sum::<usize>()
            + 1
    }

    /// Compares names using RFC 1035's ASCII case-insensitive label matching.
    ///
    /// The original label octets remain preserved even though DNS name equality
    /// is case-insensitive.
    pub fn eq_dns(&self, other: &Self) -> bool {
        let left = self.as_ref();
        let right = other.as_ref();
        std::ptr::eq(left, right)
            || (left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| left.eq_ignore_ascii_case(right)))
    }

    /// Compares names in RFC 4034 DNSSEC canonical name order.
    ///
    /// Labels are compared from the root toward the leaf as unsigned octet
    /// strings, with ASCII letters folded to lowercase.
    pub fn canonical_cmp(&self, other: &Self) -> Ordering {
        crate::protocol::resource_record::canonical_name_cmp(self, other)
    }

    /// Returns whether this name is equal to or a descendant of `ancestor`,
    /// using RFC 1035's ASCII case-insensitive label matching.
    pub fn is_descendant_of(&self, ancestor: &Self) -> bool {
        let name = self.as_ref();
        let ancestor = ancestor.as_ref();
        name.len() >= ancestor.len()
            && name[name.len() - ancestor.len()..]
                .iter()
                .zip(ancestor)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }

    /// Applies RFC 6672 DNAME substitution to a strict descendant of `owner`.
    ///
    /// Returns `Ok(None)` when the owner does not strictly enclose this name.
    /// Comparisons are DNS case-insensitive; unmatched prefix and target label
    /// octets retain their original spelling.
    ///
    /// # Errors
    /// Returns [`DomainNameError::NameTooLong`] if substitution exceeds the
    /// maximum DNS wire name length.
    pub fn dname_substitute(
        &self,
        owner: &Self,
        target: &Self,
    ) -> Result<Option<Self>, DomainNameError> {
        if self.as_ref().len() <= owner.as_ref().len() || !self.is_descendant_of(owner) {
            return Ok(None);
        }
        let prefix = self.as_ref().len() - owner.as_ref().len();
        let mut labels = Vec::with_capacity(prefix + target.as_ref().len());
        labels.extend_from_slice(&self.as_ref()[..prefix]);
        labels.extend_from_slice(target.as_ref());
        Self::from_labels(labels).map(Some)
    }
}

/// Borrows the domain name's raw label octets.
impl AsRef<[Vec<u8>]> for DomainName {
    fn as_ref(&self) -> &[Vec<u8>] {
        self.0.as_deref().map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use super::*;

    #[test]
    fn dname_substitution_matches_whole_labels_and_checks_wire_limit() {
        let owner = DomainName::from_dotted("OlD.Example").unwrap();
        let target = DomainName::from_dotted("New.Other").unwrap();
        let query =
            DomainName::from_labels(vec![vec![0xff, b'A'], b"old".to_vec(), b"EXAMPLE".to_vec()])
                .unwrap();
        let result = query.dname_substitute(&owner, &target).unwrap().unwrap();
        assert_eq!(
            result.as_ref(),
            &[vec![0xff, b'A'], b"New".to_vec(), b"Other".to_vec()]
        );
        assert_eq!(owner.dname_substitute(&owner, &target).unwrap(), None);
        assert_eq!(
            DomainName::from_dotted("notold.example")
                .unwrap()
                .dname_substitute(&owner, &target)
                .unwrap(),
            None
        );
        let long = DomainName::from_labels(vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 60],
        ])
        .unwrap();
        assert!(matches!(
            query.dname_substitute(&owner, &long),
            Err(DomainNameError::NameTooLong { .. })
        ));
        assert_eq!(
            query
                .dname_substitute(&DomainName::root(), &DomainName::root())
                .unwrap(),
            Some(query.clone())
        );
        assert_eq!(
            query
                .dname_substitute(&owner, &DomainName::root())
                .unwrap()
                .unwrap()
                .as_ref(),
            &[vec![0xff, b'A']]
        );
        let boundary = DomainName::from_labels(vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 59],
        ])
        .unwrap();
        let short = DomainName::from_dotted("x.old.example").unwrap();
        assert_eq!(
            short
                .dname_substitute(&owner, &boundary)
                .unwrap()
                .unwrap()
                .wire_len(),
            255
        );
    }

    #[test]
    fn validates_rfc1035_name_limits() {
        assert!(matches!(
            DomainName::from_labels(vec![vec![b'a'; 64]]),
            Err(DomainNameError::LabelTooLong { .. })
        ));
        assert!(matches!(
            DomainName::from_labels(vec![vec![b'a'; 63]; 4]),
            Err(DomainNameError::NameTooLong { .. })
        ));
    }

    #[test]
    fn parses_dot_separated_names_and_the_root() {
        let relative = DomainName::from_dotted("www.example").unwrap();
        let absolute = DomainName::from_dotted("www.example.").unwrap();

        assert_eq!(relative, absolute);
        assert_eq!(
            relative.as_ref(),
            [b"www".as_slice(), b"example".as_slice()]
        );
        assert!(DomainName::from_dotted(".").unwrap().as_ref().is_empty());
    }

    #[test]
    fn rejects_empty_labels_in_dot_separated_names() {
        for name in ["", "example..com", ".example", "example.."] {
            assert!(DomainName::from_dotted(name).is_err(), "accepted {name:?}");
        }
    }

    #[test]
    fn preserves_case_but_compares_dns_names_case_insensitively() {
        let mixed = DomainName::from_labels(vec![b"WWW".to_vec(), b"Example".to_vec()]).unwrap();
        let lower = DomainName::from_labels(vec![b"www".to_vec(), b"example".to_vec()]).unwrap();

        assert_eq!(mixed, lower);
        assert_eq!(mixed.as_ref()[0], b"WWW");

        let binary_upper = DomainName::from_labels(vec![vec![b'A', 0x80]]).unwrap();
        let binary_lower = DomainName::from_labels(vec![vec![b'a', 0x80]]).unwrap();
        let different_binary = DomainName::from_labels(vec![vec![b'a', 0x81]]).unwrap();
        assert_eq!(binary_upper, binary_lower);
        assert_ne!(binary_upper, different_binary);

        let hash = |name: &DomainName| {
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash(&mixed), hash(&lower));
        assert_eq!(hash(&binary_upper), hash(&binary_lower));
    }

    #[test]
    fn cloned_names_preserve_binary_octets_after_the_original_is_dropped() {
        use crate::{FromWire, IntoWire};

        let labels = vec![vec![b'A', 0, b'.', 0x80], vec![0xff, b'Z']];
        let cloned = {
            let original = DomainName::from_labels(labels.clone()).unwrap();
            original.clone()
        };
        assert_eq!(cloned.as_ref(), labels);
        let wire = cloned.into_wire().unwrap();
        assert_eq!(wire, [4, b'A', 0, b'.', 0x80, 2, 0xff, b'Z', 0]);
        assert_eq!(DomainName::from_wire(&wire).unwrap().as_ref(), labels);
        assert_eq!(
            format!("{cloned:?}"),
            "DomainName([[65, 0, 46, 128], [255, 90]])"
        );
    }

    #[test]
    fn root_remains_const_and_hash_keys_preserve_label_boundaries() {
        use std::collections::HashMap;

        const ROOT: DomainName = DomainName::root();
        let empty = DomainName::from_labels(Vec::new()).unwrap();
        assert_eq!(ROOT, empty);
        assert_eq!(ROOT.clone().wire_len(), 1);
        assert_eq!(format!("{ROOT:?}"), "DomainName([])");

        let mut names = HashMap::new();
        let first = DomainName::from_dotted("a.bc").unwrap();
        names.insert(first.clone(), 1);
        names.insert(DomainName::from_dotted("ab.c").unwrap(), 2);
        drop(first);
        assert_eq!(
            names.get(&DomainName::from_dotted("A.BC").unwrap()),
            Some(&1)
        );
        assert_eq!(
            names.get(&DomainName::from_dotted("AB.C").unwrap()),
            Some(&2)
        );
    }
}

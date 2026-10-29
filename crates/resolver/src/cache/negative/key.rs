use dns::{ClassType, DomainName};
use std::hash::{Hash, Hasher};

use crate::{cache::positive::query_types_overlap, name::packed_key};

#[derive(Clone, Eq, PartialEq)]
pub(super) enum NegativeKey {
    Name {
        qname: Box<[u8]>,
        class: ClassType,
    },
    Type {
        qname: Box<[u8]>,
        qtype: u16,
        class: ClassType,
    },
}

#[derive(Eq, Hash, PartialEq)]
pub(super) enum NegativeKeyRef<'a> {
    Name {
        qname: &'a [u8],
        class: ClassType,
    },
    Type {
        qname: &'a [u8],
        qtype: u16,
        class: ClassType,
    },
}

impl Hash for NegativeKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl NegativeKey {
    pub(super) fn as_ref(&self) -> NegativeKeyRef<'_> {
        match self {
            Self::Name { qname, class } => NegativeKeyRef::Name {
                qname,
                class: *class,
            },
            Self::Type {
                qname,
                qtype,
                class,
            } => NegativeKeyRef::Type {
                qname,
                qtype: *qtype,
                class: *class,
            },
        }
    }

    pub(super) fn owner(&self) -> &[u8] {
        match self {
            Self::Name { qname, .. } | Self::Type { qname, .. } => qname,
        }
    }

    pub(super) fn name(qname: &DomainName, class: ClassType) -> Self {
        Self::Name {
            qname: packed_key(qname),
            class,
        }
    }

    pub(super) fn qtype(qname: &DomainName, qtype: u16, class: ClassType) -> Self {
        Self::Type {
            qname: packed_key(qname),
            qtype,
            class,
        }
    }

    pub(super) fn contradicts(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Name { qname, class },
                Self::Type {
                    qname: other_name,
                    class: other_class,
                    ..
                },
            )
            | (
                Self::Type { qname, class, .. },
                Self::Name {
                    qname: other_name,
                    class: other_class,
                },
            ) => qname == other_name && class == other_class,
            _ => false,
        }
    }

    pub(super) fn conflicts_positive(
        &self,
        qname: &[u8],
        positive_types: &[u16],
        class: ClassType,
        cname: bool,
    ) -> bool {
        match self {
            Self::Name {
                qname: cached_name,
                class: cached_class,
            } => cached_name.as_ref() == qname && *cached_class == class,
            Self::Type {
                qname: cached_name,
                qtype: cached_type,
                class: cached_class,
            } => {
                cached_name.as_ref() == qname
                    && *cached_class == class
                    && (cname
                        || positive_types
                            .iter()
                            .any(|&positive_type| query_types_overlap(*cached_type, positive_type)))
            }
        }
    }
}

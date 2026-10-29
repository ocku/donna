use std::collections::HashSet;

use dns::DomainName;

/// Short CNAME chains need no allocated visited-name keys or hash table.
/// Longer chains promote to randomized hashing after eight distinct names.
#[derive(Clone, Default)]
pub(crate) struct NameSet {
    inline: [Option<DomainName>; 8],
    large: Option<HashSet<DomainName>>,
}

impl NameSet {
    pub(crate) fn from_name(name: &DomainName) -> Self {
        let mut names = Self::default();
        names.insert(name.clone());
        names
    }

    pub(crate) fn contains(&self, name: &DomainName) -> bool {
        match &self.large {
            Some(large) => large.contains(name),
            None => self.inline.iter().flatten().any(|stored| stored == name),
        }
    }

    pub(crate) fn insert(&mut self, name: DomainName) -> bool {
        if let Some(large) = &mut self.large {
            return large.insert(name);
        }
        if self.contains(&name) {
            return false;
        }
        if let Some(slot) = self.inline.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(name);
            return true;
        }
        let mut large = HashSet::with_capacity(self.inline.len() * 2);
        for slot in &mut self.inline {
            large.insert(slot.take().expect("all inline slots are occupied"));
        }
        large.insert(name);
        self.large = Some(large);
        true
    }

    pub(crate) fn extend(&mut self, names: impl IntoIterator<Item = DomainName>) {
        for name in names {
            self.insert(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::packed_key;

    #[test]
    fn promotion_preserves_binary_case_insensitive_loop_detection() {
        let mut names = NameSet::default();
        let mut packed = HashSet::new();
        let mut examples = vec![DomainName::root()];
        for index in 0..256_u16 {
            examples.push(
                DomainName::from_labels(vec![
                    vec![0, index as u8, (index >> 8) as u8, b'A', b'.', 0xff],
                    b"EXAMPLE".to_vec(),
                ])
                .unwrap(),
            );
        }
        examples.push(DomainName::from_labels(vec![vec![b'A']; 127]).unwrap());
        for name in &examples {
            assert_eq!(names.insert(name.clone()), packed.insert(packed_key(name)));
            let lower = DomainName::from_labels(
                name.as_ref()
                    .iter()
                    .map(|label| label.to_ascii_lowercase())
                    .collect(),
            )
            .unwrap();
            assert_eq!(
                names.insert(lower.clone()),
                packed.insert(packed_key(&lower))
            );
            for probe in &examples {
                assert_eq!(names.contains(probe), packed.contains(&packed_key(probe)));
            }
        }
        assert!(names.large.is_some());
    }
}

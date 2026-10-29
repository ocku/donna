use dns::DomainName;
mod visited;
pub(crate) use visited::NameSet;

/// Temporary canonical wire name for allocation-free cache probes.
pub(crate) struct PackedName {
    bytes: [u8; 255],
    len: usize,
}

impl PackedName {
    pub(crate) fn new(name: &DomainName) -> Self {
        let mut packed = Self {
            bytes: [0; 255],
            len: 0,
        };
        for label in name.as_ref() {
            packed.bytes[packed.len] = label.len() as u8;
            packed.len += 1;
            for octet in label {
                packed.bytes[packed.len] = octet.to_ascii_lowercase();
                packed.len += 1;
            }
        }
        packed.len += 1;
        packed
    }
}

impl AsRef<[u8]> for PackedName {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub(crate) fn packed_key(name: &DomainName) -> Box<[u8]> {
    pack_labels(name.as_ref(), name.wire_len())
}

pub(crate) fn packed_key_from_labels(labels: &[Vec<u8>]) -> Box<[u8]> {
    let capacity = labels.iter().map(|label| label.len() + 1).sum::<usize>() + 1;
    pack_labels(labels, capacity)
}

fn pack_labels(labels: &[Vec<u8>], capacity: usize) -> Box<[u8]> {
    let mut key = Vec::with_capacity(capacity);
    for label in labels {
        key.push(label.len() as u8);
        key.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    key.push(0);
    key.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_and_owned_keys_match_for_binary_names_and_length_boundaries() {
        for labels in [
            Vec::new(),
            vec![vec![0, b'A', 0xff], vec![b'.', b'Z']],
            vec![
                vec![b'A'; 63],
                vec![b'B'; 63],
                vec![b'C'; 63],
                vec![b'D'; 61],
            ],
            vec![vec![b'A']; 127],
        ] {
            let name = DomainName::from_labels(labels).unwrap();
            let packed = PackedName::new(&name);
            assert_eq!(packed.as_ref(), packed_key(&name).as_ref());
            let mut offset = 0;
            for suffix in 0..=name.as_ref().len() {
                assert_eq!(
                    &packed.as_ref()[offset..],
                    packed_key_from_labels(&name.as_ref()[suffix..]).as_ref()
                );
                if suffix < name.as_ref().len() {
                    offset += name.as_ref()[suffix].len() + 1;
                }
            }
        }
    }
}

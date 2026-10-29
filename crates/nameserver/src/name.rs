use dns::DomainName;

pub(crate) type DnsNameKey = Box<[u8]>;

#[cfg(test)]
thread_local! { static KEY_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
pub(crate) fn counted_keys<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    KEY_BUILDS.with(|count| count.set(0));
    let result = operation();
    (result, KEY_BUILDS.with(std::cell::Cell::get))
}

/// RFC 1035 wire-shaped, RFC 4343 ASCII-only case-folded lookup key.
pub(crate) fn dns_name_key(name: &DomainName) -> DnsNameKey {
    let mut storage = [0; 255];
    dns_name_key_into(name, &mut storage).into()
}

/// Borrowed lookup keys fit the RFC 1035 maximum uncompressed name length.
pub(crate) fn dns_name_key_into<'a>(name: &DomainName, storage: &'a mut [u8; 255]) -> &'a [u8] {
    #[cfg(test)]
    KEY_BUILDS.with(|count| count.set(count.get() + 1));
    let mut length = 0;
    for label in name.as_ref() {
        storage[length] = label.len() as u8;
        length += 1;
        for octet in label {
            storage[length] = octet.to_ascii_lowercase();
            length += 1;
        }
    }
    storage[length] = 0;
    &storage[..length + 1]
}

pub(crate) fn suffixes(key: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::successors(Some(key), |suffix| {
        let length = usize::from(suffix[0]);
        (length != 0).then(|| &suffix[length + 1..])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_keys_preserve_binary_case_and_maximum_names() {
        for labels in [
            vec![],
            vec![b"MiXeD".to_vec(), vec![0, 255, b'A', b'.']],
            vec![vec![255; 63], vec![b'Z'; 63], vec![0; 63], vec![b'A'; 61]],
            vec![vec![b'A']; 127],
        ] {
            let name = DomainName::from_labels(labels.clone()).unwrap();
            let expected = labels
                .iter()
                .flat_map(|label| {
                    std::iter::once(label.len() as u8)
                        .chain(label.iter().map(u8::to_ascii_lowercase))
                })
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let mut storage = [42; 255];
            assert_eq!(dns_name_key_into(&name, &mut storage), expected);
            assert_eq!(dns_name_key(&name).as_ref(), expected);
        }
    }
}

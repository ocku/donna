use super::*;

#[test]
fn borrowed_signature_matching_preserves_constructed_wildcard_semantics() {
    let mut names = vec![DomainName::root()];
    for labels in [
        vec![b"*".to_vec()],
        vec![b"www".to_vec(), b"example".to_vec(), b"test".to_vec()],
        vec![b"*".to_vec(), b"EXAMPLE".to_vec(), b"TEST".to_vec()],
        vec![
            b"p".to_vec(),
            b"q".to_vec(),
            b"example".to_vec(),
            b"test".to_vec(),
        ],
        vec![vec![b'A', 0, 255], vec![255, b'Z']],
        vec![vec![255; 63], vec![0; 63], vec![b'A'; 63], vec![b'z'; 61]],
        vec![vec![b'A']; 127],
    ] {
        names.push(DomainName::from_labels(labels).unwrap());
    }
    for owner in &names {
        for labels in 0..=u8::MAX {
            let wildcard = (usize::from(labels) < owner.as_ref().len())
                .then(|| {
                    let mut source = vec![b"*".to_vec()];
                    source.extend_from_slice(
                        &owner.as_ref()[owner.as_ref().len() - usize::from(labels)..],
                    );
                    DomainName::from_labels(source).ok()
                })
                .flatten();
            for source in names.iter().chain(wildcard.iter()) {
                let expected = source.eq_dns(owner)
                    || wildcard
                        .as_ref()
                        .is_some_and(|wildcard| source.eq_dns(wildcard));
                assert_eq!(
                    rrsig_source_matches(source, owner, labels),
                    expected,
                    "source={source:?}, owner={owner:?}, labels={labels}"
                );
            }
        }
    }
}

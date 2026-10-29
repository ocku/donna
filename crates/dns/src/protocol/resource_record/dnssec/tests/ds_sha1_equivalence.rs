use super::*;

#[test]
fn ds_sha1_matches_independent_ring_digest_for_wire_names_and_key_lengths() {
    let owners = [
        DomainName::root(),
        DomainName::from_dotted("MiXeD.Example.Test.").unwrap(),
        DomainName::from_labels(vec![vec![0, 255, b'A'], vec![b'Z'; 63]]).unwrap(),
        DomainName::from_labels(vec![
            vec![b'X'; 63],
            vec![b'y'; 63],
            vec![b'Z'; 63],
            vec![b'A'; 61],
        ])
        .unwrap(),
    ];
    for owner in owners {
        for size in [
            0, 1, 31, 32, 55, 56, 63, 64, 65, 127, 128, 255, 256, 512, 1024, 4096,
        ] {
            for flags in [256_u16, 257, 0xffff] {
                let key = Dnskey {
                    flags,
                    protocol: 3,
                    algorithm: 8,
                    public_key: (0..size).map(|n| (n * 37 + 19) as u8).collect(),
                };
                let mut wire = Vec::new();
                for label in owner.as_ref() {
                    wire.push(label.len() as u8);
                    wire.extend(label.iter().map(u8::to_ascii_lowercase));
                }
                wire.push(0);
                wire.extend(flags.to_be_bytes());
                wire.extend([key.protocol, key.algorithm]);
                wire.extend(&key.public_key);
                let expected = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &wire);
                let ds = key.to_ds(&owner, 1).unwrap();
                assert_eq!(ds.digest, expected.as_ref(), "owner={owner:?} size={size}");
                assert_eq!(ds.digest_type, 1);
                assert_eq!(ds.algorithm, key.algorithm);
                assert_eq!(ds.key_tag, key.key_tag());
                assert!(ds.matches_dnskey(&owner, &key).unwrap());
            }
        }
    }
}

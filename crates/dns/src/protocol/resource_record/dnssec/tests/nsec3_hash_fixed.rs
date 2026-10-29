use super::*;

// Retain the original concatenation algorithm independently of the new
// fixed-storage implementation and its public Vec-returning wrappers.
fn reference(
    name: &DomainName,
    algorithm: u8,
    iterations: u16,
    salt: &[u8],
    maximum: u16,
) -> Result<Vec<u8>, Nsec3HashError> {
    if algorithm != 1 {
        return Err(Nsec3HashError::UnsupportedAlgorithm { algorithm });
    }
    if iterations > maximum {
        return Err(Nsec3HashError::TooManyIterations {
            iterations,
            maximum,
        });
    }
    if salt.len() > usize::from(u8::MAX) {
        return Err(Nsec3HashError::SaltTooLong { length: salt.len() });
    }
    let mut input = Vec::new();
    for label in name.as_ref() {
        input.push(label.len() as u8);
        input.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    input.push(0);
    input.extend_from_slice(salt);
    let mut digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input)
        .as_ref()
        .to_vec();
    for _ in 0..iterations {
        digest.extend_from_slice(salt);
        digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &digest)
            .as_ref()
            .to_vec();
    }
    Ok(digest)
}

#[test]
fn fixed_nsec3_hash_matches_original_for_names_salts_flags_algorithms_and_limits() {
    let names = [
        DomainName::root(),
        name("MiXeD.ExAmPlE."),
        DomainName::from_labels(vec![vec![0, 255, b'A', 0xc0], b"Example".to_vec()]).unwrap(),
        DomainName::from_labels(vec![vec![b'A']; 127]).unwrap(),
        DomainName::from_labels(vec![
            vec![b'Z'; 63],
            vec![0; 63],
            vec![255; 63],
            vec![b'A'; 61],
        ])
        .unwrap(),
    ];
    for name in &names {
        for salt in [
            Vec::new(),
            vec![0xa1, 0xb2],
            vec![0xff; 255],
            vec![0x5a; 256],
            vec![0x5a; 512],
        ] {
            for algorithm in [0, 1, 2, 255] {
                for iterations in [0_u16, 1, 2, 12, 64] {
                    for maximum in [0, iterations.saturating_sub(1), iterations, iterations + 1] {
                        let expected = reference(name, algorithm, iterations, &salt, maximum);
                        for flags in [0, 1, 128, 255] {
                            let parameter = Nsec3param {
                                hash_algorithm: algorithm,
                                flags,
                                iterations,
                                salt: salt.clone(),
                            };
                            let record = Nsec3 {
                                hash_algorithm: algorithm,
                                flags,
                                iterations,
                                salt: salt.clone(),
                                next_hashed_owner_name: vec![0; 20],
                                type_bitmap: None,
                            };
                            assert_eq!(
                                parameter.hash_name_fixed(name, maximum).map(|d| d.to_vec()),
                                expected
                            );
                            assert_eq!(
                                record.hash_name_fixed(name, maximum).map(|d| d.to_vec()),
                                expected
                            );
                            assert_eq!(parameter.hash_name(name, maximum), expected);
                            assert_eq!(record.hash_name(name, maximum), expected);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn fixed_nsec3_hash_retains_published_rfc5155_example() {
    let parameters = Nsec3param {
        hash_algorithm: 1,
        flags: 0,
        iterations: 12,
        salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
    };
    let expected = decode_base32hex_label(b"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom").unwrap();
    assert_eq!(
        parameters
            .hash_name_fixed(&name("example."), 12)
            .unwrap()
            .as_slice(),
        expected
    );
    assert_eq!(
        parameters
            .hash_name_fixed(&name("EXAMPLE."), 12)
            .unwrap()
            .as_slice(),
        expected
    );
}

#[test]
fn fixed_nsec3_hash_checks_resource_limits_before_hashing() {
    for algorithm in [0, 1, 2, 255] {
        let parameters = Nsec3param {
            hash_algorithm: algorithm,
            flags: 255,
            iterations: u16::MAX,
            salt: vec![0; 512],
        };
        let expected = if algorithm == 1 {
            Nsec3HashError::TooManyIterations {
                iterations: u16::MAX,
                maximum: u16::MAX - 1,
            }
        } else {
            Nsec3HashError::UnsupportedAlgorithm { algorithm }
        };
        assert_eq!(
            parameters.hash_name_fixed(&DomainName::root(), u16::MAX - 1),
            Err(expected)
        );
        assert_eq!(
            parameters.hash_name(&DomainName::root(), u16::MAX - 1),
            Err(expected)
        );
    }
}

#[test]
fn suffix_hashes_match_independent_original_hash_for_every_validated_suffix() {
    for name in [
        DomainName::root(),
        name("a.B.C.Example."),
        DomainName::from_labels(vec![vec![0, 255, b'A']; 40]).unwrap(),
        DomainName::from_labels(vec![vec![b'Z']; 127]).unwrap(),
    ] {
        for salt in [vec![], vec![0xab; 255], vec![0xcd; 512]] {
            for (algorithm, iterations, maximum) in [(1, 0, 0), (1, 12, 12), (1, 12, 0), (2, 12, 0)]
            {
                let parameters = Nsec3param {
                    hash_algorithm: algorithm,
                    flags: 0,
                    iterations,
                    salt: salt.clone(),
                };
                let actual = parameters
                    .hash_name_suffixes_fixed(&name, maximum)
                    .collect::<Vec<_>>();
                assert_eq!(actual.len(), name.as_ref().len() + 1);
                for (dropped, actual) in actual.into_iter().enumerate() {
                    let suffix =
                        DomainName::from_labels(name.as_ref()[dropped..].to_vec()).unwrap();
                    assert_eq!(
                        actual.map(|digest| digest.to_vec()),
                        reference(&suffix, algorithm, iterations, &salt, maximum)
                    );
                }
            }
        }
    }
}

#[test]
fn oversized_salts_are_rejected_by_every_hash_entry_point() {
    let owner = name("www.example.");
    for length in [256, 512] {
        let parameter = Nsec3param {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: vec![0; length],
        };
        let record = Nsec3 {
            hash_algorithm: parameter.hash_algorithm,
            flags: 0,
            iterations: parameter.iterations,
            salt: parameter.salt.clone(),
            next_hashed_owner_name: vec![0; 20],
            type_bitmap: None,
        };
        let error = Nsec3HashError::SaltTooLong { length };
        assert_eq!(parameter.hash_name(&owner, 0), Err(error));
        assert_eq!(record.hash_name(&owner, 0), Err(error));
        assert_eq!(parameter.hash_name_fixed(&owner, 0), Err(error));
        assert_eq!(record.hash_name_fixed(&owner, 0), Err(error));
        assert_eq!(parameter.hash_name_label(&owner, 0), Err(error));
        assert_eq!(record.hash_name_label(&owner, 0), Err(error));
        assert!(
            parameter
                .hash_name_suffixes_fixed(&owner, 0)
                .all(|hash| hash == Err(error))
        );
    }
}

use super::*;

#[test]
fn sha512_matches_independent_ring_for_certificate_and_public_key_selectors() {
    for length in [
        0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 255, 256, 512, 1024, 4096,
    ] {
        let certificate: Vec<_> = (0..length).map(|i| (i * 13 + 7) as u8).collect();
        let spki: Vec<_> = (0..length).map(|i| (i * 37 + 5) as u8).collect();
        let material = CertificateMaterial {
            certificate_der: &certificate,
            subject_public_key_info_der: &spki,
        };
        for (selector, selected) in [(0, &certificate), (1, &spki)] {
            let digest = ring::digest::digest(&ring::digest::SHA512, selected);
            let mut association = CertificateAssociation {
                certificate_usage: 3,
                selector,
                matching_type: 2,
                association_data: digest.as_ref().to_vec(),
            };
            assert!(
                association
                    .matches(DnssecSecurityStatus::Secure, &certificate, &spki)
                    .unwrap()
            );
            for usage in 0..=3 {
                association.certificate_usage = usage;
                assert!(
                    association
                        .evaluate_path(
                            DnssecSecurityStatus::Secure,
                            material,
                            &[material],
                            true,
                            true
                        )
                        .unwrap()
                );
            }
            association.association_data[0] ^= 1;
            assert!(
                !association
                    .matches(DnssecSecurityStatus::Secure, &certificate, &spki)
                    .unwrap()
            );
            assert!(
                !association
                    .evaluate_path(
                        DnssecSecurityStatus::Secure,
                        material,
                        &[material],
                        true,
                        true
                    )
                    .unwrap()
            );
            assert!(matches!(
                association.matches(DnssecSecurityStatus::Insecure, &certificate, &spki),
                Err(CertificateAssociationError::Unauthenticated(_))
            ));
            association.association_data.clear();
            assert!(
                !association
                    .matches(DnssecSecurityStatus::Secure, &certificate, &spki)
                    .unwrap()
            );
        }
    }
}

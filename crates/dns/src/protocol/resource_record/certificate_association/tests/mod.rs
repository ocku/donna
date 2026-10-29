mod sha512;
mod smimea_sha256;

use super::*;

fn name(value: &str) -> DomainName {
    DomainName::from_dotted(value).unwrap()
}

#[test]
fn constructs_rfc_owner_names() {
    assert_eq!(
        tlsa_owner_name(&name("www.example.com"), 443, TlsaTransport::Tcp).unwrap(),
        name("_443._tcp.www.example.com")
    );
    assert_eq!(
        smimea_owner_name("hugh", &name("example.com")).unwrap(),
        name("c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._smimecert.example.com")
    );
}

#[test]
fn tlsa_owners_accept_digit_leading_and_numeric_host_labels() {
    for host in [
        "3com.example",
        "host.123.example",
        "123.example",
        "3-host.example",
    ] {
        assert_eq!(
            tlsa_owner_name(&name(host), 443, TlsaTransport::Tcp).unwrap(),
            name(&format!("_443._tcp.{host}")),
        );
    }
    for host in [
        "-host.example",
        "host-.example",
        "host.-123.example",
        "host.123-.example",
        "host_name.example",
        ".",
    ] {
        assert_eq!(
            tlsa_owner_name(&name(host), 443, TlsaTransport::Tcp),
            Err(CertificateAssociationError::InvalidHostName)
        );
    }
    let non_ascii = DomainName::from_labels(vec![vec![0xff], b"example".to_vec()]).unwrap();
    assert_eq!(
        tlsa_owner_name(&non_ascii, 443, TlsaTransport::Tcp),
        Err(CertificateAssociationError::InvalidHostName)
    );
    assert!(!valid_host_label(b""));
}

#[test]
fn matching_requires_secure_dns_and_supports_all_defined_selectors_and_hashes() {
    let certificate = b"certificate";
    let spki = b"subject-public-key-info";
    for (selector, selected) in [(0, certificate.as_slice()), (1, spki.as_slice())] {
        for matching_type in 0..=2 {
            let association_data = match matching_type {
                0 => selected.to_vec(),
                1 => ring::digest::digest(&ring::digest::SHA256, selected)
                    .as_ref()
                    .to_vec(),
                2 => ring::digest::digest(&ring::digest::SHA512, selected)
                    .as_ref()
                    .to_vec(),
                _ => unreachable!(),
            };
            let association = CertificateAssociation {
                certificate_usage: 3,
                selector,
                matching_type,
                association_data,
            };
            assert!(
                association
                    .matches(DnssecSecurityStatus::Secure, certificate, spki)
                    .unwrap()
            );
            assert!(matches!(
                association.matches(DnssecSecurityStatus::Insecure, certificate, spki),
                Err(CertificateAssociationError::Unauthenticated(_))
            ));
        }
    }
}

#[test]
fn usage_policy_requires_the_corresponding_path_validation() {
    let end_entity = CertificateMaterial {
        certificate_der: b"end",
        subject_public_key_info_der: b"end-key",
    };
    let issuer = CertificateMaterial {
        certificate_der: b"issuer",
        subject_public_key_info_der: b"issuer-key",
    };
    let mut association = CertificateAssociation {
        certificate_usage: 0,
        selector: 0,
        matching_type: 0,
        association_data: b"issuer".to_vec(),
    };
    assert!(
        association
            .evaluate_path(
                DnssecSecurityStatus::Secure,
                end_entity,
                &[issuer],
                true,
                false,
            )
            .unwrap()
    );
    assert!(
        !association
            .evaluate_path(
                DnssecSecurityStatus::Secure,
                end_entity,
                &[issuer],
                false,
                false,
            )
            .unwrap()
    );

    association.certificate_usage = 2;
    assert!(
        association
            .evaluate_path(
                DnssecSecurityStatus::Secure,
                end_entity,
                &[issuer],
                false,
                true,
            )
            .unwrap()
    );
}

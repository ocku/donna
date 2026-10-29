use super::*;
use crate::master::MasterFile;
use rsa::{
    pkcs8::EncodePrivateKey,
    rand_core::{CryptoRng, Error as RandomError, RngCore},
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
};
struct TestRng(u64);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        self.fill_bytes(destination);
        Ok(())
    }
}
impl CryptoRng for TestRng {}
fn name(value: &str) -> DomainName {
    DomainName::from_dotted(value).unwrap()
}
fn authenticated_test_zone(
    zone: &DomainName,
) -> (AuthenticatedDnskeySet, rsa::RsaPrivateKey, Dnskey) {
    let mut rng = TestRng(0x3141_5926_5358_9793);
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let exponent = private_key.e().to_bytes_be();
    let modulus = private_key.n().to_bytes_be();
    let mut public_key = vec![exponent.len() as u8];
    public_key.extend_from_slice(&exponent);
    public_key.extend_from_slice(&modulus);
    let dnskey = Dnskey {
        flags: Dnskey::ZONE_KEY_FLAG,
        protocol: 3,
        algorithm: 8,
        public_key,
    };
    let key_record = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::DNSKEY,
        class: ClassType::IN,
        ttl: 3_600,
        rdata: RData::DNSKEY(dnskey.clone()),
    };
    (
        AuthenticatedDnskeySet {
            zone: zone.clone(),
            class: ClassType::IN,
            records: vec![key_record].into(),
            authenticated_ttl: 3_600,
            signature_expiration: u32::MAX,
            soa_signature: Default::default(),
            dname_signature: Default::default(),
            denial_signatures: None,
        },
        private_key,
        dnskey,
    )
}
fn sign_record(
    record: &ResourceRecord,
    zone: &DomainName,
    dnskey: &Dnskey,
    private_key: &rsa::RsaPrivateKey,
) -> ResourceRecord {
    let mut rrsig = Rrsig {
        type_covered: u16::from(record.rtype),
        algorithm: 8,
        labels: record.name.as_ref().len() as u8,
        original_ttl: record.ttl,
        signature_expiration: 10_000,
        signature_inception: 0,
        key_tag: dnskey.key_tag(),
        signer_name: zone.clone(),
        signature: Vec::new(),
    };
    let signed_data = rrsig.signed_data(std::slice::from_ref(record)).unwrap();
    rrsig.signature = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private_key.clone())
        .sign(&signed_data)
        .to_vec();
    ResourceRecord {
        name: record.name.clone(),
        rtype: RecordType::RRSIG,
        class: record.class,
        ttl: record.ttl,
        rdata: RData::RRSIG(rrsig),
    }
}
#[test]
fn exposes_rfc6944_status_and_supports_its_mandatory_algorithm() {
    assert_eq!(
        rfc6944_algorithm_status(1),
        DnssecAlgorithmStatus::MustNotImplement
    );
    assert_eq!(
        rfc6944_algorithm_status(5),
        DnssecAlgorithmStatus::MustImplement
    );
    assert_eq!(
        rfc6944_algorithm_status(8),
        DnssecAlgorithmStatus::Recommended
    );
    assert_eq!(
        rfc6944_algorithm_status(15),
        DnssecAlgorithmStatus::Optional
    );
    assert!(supports_dnssec_algorithm(5));
    assert!(supports_dnssec_algorithm(7));
    assert!(supports_dnssec_algorithm(8));
    assert!(supports_dnssec_algorithm(13));
    assert!(!supports_dnssec_algorithm(1));
}
#[test]
fn authenticated_keys_validate_the_rfc5702_rrset_and_bound_its_ttl() {
    let file = MasterFile::parse(
        concat!(
            "example.net. 7200 IN DNSKEY 256 3 8 ( ",
            "AwEAAcFcGsaxxdgiuuGmCkVI my4h99CqT7jwY3pexPGcnUFt ",
            "R2Fh36BponcwtkZ4cAgtvd4Qs8P kxUdp6p/DlUmObdk= )\n",
            "www.example.net. 3600 IN A 192.0.2.91\n",
            "www.example.net. 1800 IN RRSIG A 8 3 3600 ",
            "20300101000000 20000101000000 9033 example.net. ( ",
            "kRCOH6u7l0QGy9qpC9 l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa ",
            "cFYK/lPtPiVYP4bwg== )",
        ),
        None,
    )
    .unwrap();
    let keys = AuthenticatedDnskeySet {
        zone: name("example.net"),
        class: ClassType::IN,
        records: file.records[0..1].to_vec().into(),
        authenticated_ttl: 7_200,
        signature_expiration: u32::MAX,
        soa_signature: Default::default(),
        dname_signature: Default::default(),
        denial_signatures: None,
    };
    let outcome = keys.validate_rrset(&file.records[1..2], &file.records[2..3], 1_577_836_800);
    assert_eq!(outcome.status(), DnssecSecurityStatus::Secure);
    let authenticated = outcome.secure().unwrap();
    assert_eq!(authenticated.authenticated_ttl(), 1_800);
    assert_eq!(authenticated.signing_key_tag(), 9_033);
    assert!(authenticated.wildcard_closest_encloser().is_none());
}
#[test]
fn delegation_status_distinguishes_unsupported_and_bogus_paths() {
    let dnskey = Dnskey {
        flags: Dnskey::ZONE_KEY_FLAG,
        protocol: 3,
        algorithm: 8,
        public_key: vec![1],
    };
    let record = ResourceRecord {
        name: name("child.example"),
        rtype: RecordType::DNSKEY,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::DNSKEY(dnskey),
    };
    let unsupported = Ds {
        key_tag: 1,
        algorithm: 15,
        digest_type: 2,
        digest: vec![0; 32],
    };
    assert_eq!(
        authenticate_dnskey_with_ds(
            &name("child.example"),
            ClassType::IN,
            std::slice::from_ref(&record),
            &[],
            &[unsupported],
            1,
        )
        .status(),
        DnssecSecurityStatus::Insecure
    );
    let mismatched = Ds {
        key_tag: 1,
        algorithm: 8,
        digest_type: 2,
        digest: vec![0; 32],
    };
    assert_eq!(
        authenticate_dnskey_with_ds(
            &name("child.example"),
            ClassType::IN,
            &[record],
            &[],
            &[mismatched],
            1,
        )
        .status(),
        DnssecSecurityStatus::Bogus
    );
}
#[test]
fn authenticates_a_dnskey_rrset_from_ds_and_dnskey_trust_anchors() {
    let zone = name("child.example");
    let mut rng = TestRng(0x5eed_cafe_f00d_beef);
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let exponent = private_key.e().to_bytes_be();
    let modulus = private_key.n().to_bytes_be();
    let mut public_key = vec![exponent.len() as u8];
    public_key.extend_from_slice(&exponent);
    public_key.extend_from_slice(&modulus);
    let dnskey = Dnskey {
        flags: Dnskey::ZONE_KEY_FLAG | Dnskey::SECURE_ENTRY_POINT_FLAG,
        protocol: 3,
        algorithm: 8,
        public_key,
    };
    let key_record = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::DNSKEY,
        class: ClassType::IN,
        ttl: 3_600,
        rdata: RData::DNSKEY(dnskey.clone()),
    };
    let mut rrsig = Rrsig {
        type_covered: u16::from(RecordType::DNSKEY),
        algorithm: 8,
        labels: 2,
        original_ttl: 3_600,
        signature_expiration: 10_000,
        signature_inception: 0,
        key_tag: dnskey.key_tag(),
        signer_name: zone.clone(),
        signature: Vec::new(),
    };
    let signed_data = rrsig
        .signed_data(std::slice::from_ref(&key_record))
        .unwrap();
    rrsig.signature = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private_key)
        .sign(&signed_data)
        .to_vec();
    let signature_record = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl: 3_600,
        rdata: RData::RRSIG(rrsig),
    };
    let ds = dnskey.to_ds(&zone, 2).unwrap();

    let mut bad_signature = signature_record.clone();
    let RData::RRSIG(bad_rrsig) = &mut bad_signature.rdata else {
        unreachable!()
    };
    bad_rrsig.signature[0] ^= 0xff;

    let from_ds = authenticate_dnskey_with_ds(
        &zone,
        ClassType::IN,
        std::slice::from_ref(&key_record),
        &[bad_signature, signature_record.clone()],
        &[ds],
        100,
    );
    assert_eq!(from_ds.status(), DnssecSecurityStatus::Secure);
    assert_eq!(from_ds.secure().unwrap().records().len(), 1);

    let from_anchor = authenticate_dnskey_with_anchor(
        &zone,
        ClassType::IN,
        &[key_record],
        &[signature_record],
        &dnskey,
        100,
    );
    assert_eq!(from_anchor.status(), DnssecSecurityStatus::Secure);
}

#[test]
fn rsa_signing_keys_emit_dnskeys_and_verifiable_sha1_and_sha2_rrsigs() {
    let mut rng = TestRng(0x2718_2818_2845_9045);
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let pkcs8 = private_key.to_pkcs8_der().unwrap();
    let zone = name("example");
    let record = ResourceRecord {
        name: name("www.example"),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 3_600,
        rdata: RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    };

    for algorithm in [5, 7, 8, 10] {
        let signing_key = crate::RsaDnssecSigningKey::from_pkcs8_der(
            Dnskey::ZONE_KEY_FLAG,
            algorithm,
            pkcs8.as_bytes(),
        )
        .unwrap();
        let signature = signing_key
            .sign_rrset(std::slice::from_ref(&record), &zone, 100, 10_000)
            .unwrap();
        assert_eq!(signature.algorithm, algorithm);
        assert_eq!(signature.labels, 2);
        signature
            .verify(
                std::slice::from_ref(&record),
                &zone,
                signing_key.dnskey(),
                1_000,
            )
            .unwrap();
    }

    assert!(matches!(
        crate::RsaDnssecSigningKey::from_pkcs8_der(Dnskey::ZONE_KEY_FLAG, 15, pkcs8.as_bytes(),),
        Err(crate::RrsigSigningError::UnsupportedAlgorithm { algorithm: 15 })
    ));
    assert!(matches!(
        crate::RsaDnssecSigningKey::from_pkcs8_der(0, 8, pkcs8.as_bytes()),
        Err(crate::RrsigSigningError::InvalidFlags { flags: 0 })
    ));
}

#[test]
fn authenticates_rfc4035_nsec_name_error_and_nodata_proofs() {
    let zone = name("example");
    let (keys, private_key, dnskey) = authenticated_test_zone(&zone);
    let file = MasterFile::parse(
        concat!(
            "b.example. 3600 IN NSEC ns1.example. NS RRSIG NSEC\n",
            "example. 3600 IN NSEC a.example. NS SOA MX RRSIG NSEC DNSKEY\n",
            "ns1.example. 3600 IN NSEC ns2.example. A RRSIG NSEC",
        ),
        None,
    )
    .unwrap();
    let signatures = file
        .records
        .iter()
        .map(|record| sign_record(record, &zone, &dnskey, &private_key))
        .collect::<Vec<_>>();

    let name_error =
        keys.validate_nsec_name_error(&name("ml.example"), &file.records, &signatures, 100);
    assert_eq!(name_error.status(), DnssecSecurityStatus::Secure);
    let proof = name_error.secure().unwrap();
    assert_eq!(proof.kind(), DnssecDenialKind::NameError);
    assert_eq!(proof.proof_record_indices(), &[0, 1]);

    let nodata = keys.validate_nsec_nodata(
        &name("ns1.example"),
        u16::from(RecordType::MX),
        &file.records,
        &signatures,
        100,
    );
    assert_eq!(nodata.status(), DnssecSecurityStatus::Secure);
    assert_eq!(nodata.secure().unwrap().kind(), DnssecDenialKind::NoData);

    let missing_signature = keys.validate_nsec_nodata(
        &name("ns1.example"),
        u16::from(RecordType::MX),
        &file.records,
        &signatures[..2],
        100,
    );
    assert_eq!(missing_signature.status(), DnssecSecurityStatus::Bogus);

    let wildcard_file = MasterFile::parse(
        "x.y.w.example. 3600 IN NSEC xx.example. MX RRSIG NSEC",
        None,
    )
    .unwrap();
    let wildcard_signature = sign_record(&wildcard_file.records[0], &zone, &dnskey, &private_key);
    let wildcard = keys.validate_nsec_wildcard_expansion(
        &name("a.z.w.example"),
        &name("w.example"),
        &wildcard_file.records,
        &[wildcard_signature],
        100,
    );
    assert_eq!(wildcard.status(), DnssecSecurityStatus::Secure);
    assert_eq!(
        wildcard.secure().unwrap().kind(),
        DnssecDenialKind::WildcardExpansion
    );
}

#[test]
fn authenticates_the_rfc5155_nsec3_name_error_and_nodata_proofs() {
    let zone = name("example");
    let (keys, private_key, dnskey) = authenticated_test_zone(&zone);
    let file = MasterFile::parse(
        concat!(
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 1 1 12 aabbccdd ",
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG\n",
            "b4um86eghhds6nea196smvmlo4ors995.example. 3600 IN NSEC3 1 1 12 aabbccdd ",
            "gjeqe526plbf1g8mklp59enfd789njgi MX RRSIG\n",
            "35mthgpgcu1qg68fab165klnsnk3dpvl.example. 3600 IN NSEC3 1 1 12 aabbccdd ",
            "b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG\n",
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 3600 IN NSEC3 1 1 12 aabbccdd ",
            "35mthgpgcu1qg68fab165klnsnk3dpvl A RRSIG",
        ),
        None,
    )
    .unwrap();
    let signatures = file
        .records
        .iter()
        .map(|record| sign_record(record, &zone, &dnskey, &private_key))
        .collect::<Vec<_>>();

    let name_error = keys.validate_nsec3_name_error(
        &name("a.c.x.w.example"),
        &file.records,
        &signatures,
        100,
        12,
    );
    assert_eq!(name_error.status(), DnssecSecurityStatus::Secure);
    assert!(name_error.secure().unwrap().opt_out());
    assert_eq!(
        name_error.secure().unwrap().proof_record_indices(),
        &[0, 1, 2]
    );

    let nodata = keys.validate_nsec3_nodata(
        &name("ns1.example"),
        u16::from(RecordType::MX),
        &file.records,
        &signatures,
        100,
        12,
    );
    assert_eq!(nodata.status(), DnssecSecurityStatus::Secure);
    assert!(!nodata.secure().unwrap().opt_out());
    assert_eq!(nodata.secure().unwrap().proof_record_indices(), &[3]);

    let bounded = keys.validate_nsec3_name_error(
        &name("a.c.x.w.example"),
        &file.records,
        &signatures,
        100,
        11,
    );
    assert_eq!(bounded.status(), DnssecSecurityStatus::Bogus);

    let opt_out = keys.validate_nsec3_insecure_delegation(
        &name("c.example"),
        &file.records,
        &signatures,
        100,
        12,
    );
    assert_eq!(opt_out.status(), DnssecSecurityStatus::Secure);
    assert_eq!(
        opt_out.secure().unwrap().kind(),
        DnssecDenialKind::UnsignedDelegation
    );
    assert_eq!(opt_out.secure().unwrap().proof_record_indices(), &[0, 2]);

    let wildcard = keys.validate_nsec3_wildcard_expansion(
        &name("a.c.x.w.example"),
        &name("x.w.example"),
        &file.records,
        &signatures,
        100,
        12,
    );
    assert_eq!(wildcard.status(), DnssecSecurityStatus::Secure);
    assert_eq!(wildcard.secure().unwrap().proof_record_indices(), &[0]);
}

mod wildcard_nodata;

mod empty_nonterminal;

mod soa_cache;

mod dname_signature;

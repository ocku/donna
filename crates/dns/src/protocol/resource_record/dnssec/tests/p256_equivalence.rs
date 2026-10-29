use super::super::verification::verify_ecdsa_p256;
use super::RrsigVerificationError;
use p256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer, Verifier},
};

// The former verifier is the differential oracle for acceptance and errors.
fn reference(key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), RrsigVerificationError> {
    if key.len() != 64 {
        return Err(RrsigVerificationError::MalformedPublicKey);
    }
    let mut encoded = [0; 65];
    encoded[0] = 4;
    encoded[1..].copy_from_slice(key);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
        .map_err(|_| RrsigVerificationError::MalformedPublicKey)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| RrsigVerificationError::BadSignature)?;
    key.verify(data, &signature)
        .map_err(|_| RrsigVerificationError::BadSignature)
}

fn outcome(result: Result<(), RrsigVerificationError>) -> u8 {
    match result {
        Ok(()) => 0,
        Err(RrsigVerificationError::MalformedPublicKey) => 1,
        Err(RrsigVerificationError::BadSignature) => 2,
        other => panic!("unexpected P-256 outcome {other:?}"),
    }
}

fn compare(key: &[u8], data: &[u8], signature: &[u8]) {
    assert_eq!(
        outcome(verify_ecdsa_p256(key, data, signature)),
        outcome(reference(key, data, signature))
    );
}

fn hex(text: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

fn order() -> [u8; 32] {
    hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
}

fn opposite_s(signature: &[u8]) -> [u8; 64] {
    let mut other: [u8; 64] = signature.try_into().unwrap();
    let mut borrow = 0_i16;
    for i in (0..32).rev() {
        let value = i16::from(order()[i]) - i16::from(signature[32 + i]) - borrow;
        other[32 + i] = value as u8;
        borrow = i16::from(value < 0);
    }
    assert_eq!(borrow, 0);
    other
}

#[test]
fn valid_changed_high_and_low_s_signatures_match_the_previous_verifier() {
    for scalar in 1..=16 {
        let key = SigningKey::from_slice(&[scalar; 32]).unwrap();
        let encoded = key.verifying_key().to_encoded_point(false);
        let public = &encoded.as_bytes()[1..];
        for data in [
            &b""[..],
            &b"DNSSEC canonical signed data"[..],
            &[scalar; 137][..],
        ] {
            let signature: Signature = key.sign(data);
            let bytes = signature.to_bytes();
            let other = opposite_s(&bytes);
            assert!(reference(public, data, &bytes).is_ok());
            assert!(reference(public, data, &other).is_ok());
            assert!(verify_ecdsa_p256(public, data, &bytes).is_ok());
            assert!(verify_ecdsa_p256(public, data, &other).is_ok());
            compare(public, b"different data", &bytes);
            let mut changed = bytes;
            changed[17] ^= 0x80;
            compare(public, data, &changed);
        }
    }
}

#[test]
fn scalar_ranges_framing_and_malformed_key_error_precedence_match() {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let encoded = key.verifying_key().to_encoded_point(false);
    let public = &encoded.as_bytes()[1..];
    let data = b"fixed-width DNSSEC signature";
    let signature: Signature = key.sign(data);
    let bytes = signature.to_bytes();
    let mut n_minus_one = order();
    n_minus_one[31] -= 1;
    let mut one = [0; 32];
    one[31] = 1;
    let scalars = [[0; 32], one, n_minus_one, order(), [0xff; 32]];
    let mut signatures = vec![
        vec![],
        bytes[..63].to_vec(),
        bytes.to_vec(),
        [&bytes[..], &[0]].concat(),
    ];
    for r in scalars {
        for s in scalars {
            signatures.push([r, s].concat());
        }
    }
    let mut points = vec![
        public.to_vec(),
        vec![],
        public[..63].to_vec(),
        [public, &[0]].concat(),
        vec![0; 64],
        vec![0xff; 64],
    ];
    let prime = hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    for coordinate in [0, 32] {
        let mut point = public.to_vec();
        point[coordinate..coordinate + 32].copy_from_slice(&prime);
        points.push(point);
    }
    let mut off_curve = public.to_vec();
    off_curve[63] ^= 1;
    points.push(off_curve);
    for point in points {
        for signature in &signatures {
            compare(&point, data, signature);
        }
        if outcome(reference(&point, data, &bytes)) == 1 {
            assert!(matches!(
                verify_ecdsa_p256(&point, data, &[]),
                Err(RrsigVerificationError::MalformedPublicKey)
            ));
        }
    }
}

#[test]
fn valid_leading_zero_scalar_bytes_are_retained() {
    let key = SigningKey::from_slice(&[11; 32]).unwrap();
    let encoded = key.verifying_key().to_encoded_point(false);
    for value in 0_u32..4096 {
        let data = value.to_be_bytes();
        let signature: Signature = key.sign(&data);
        let bytes = signature.to_bytes();
        if bytes[0] == 0 || bytes[32] == 0 {
            assert!(reference(&encoded.as_bytes()[1..], &data, &bytes).is_ok());
            assert!(verify_ecdsa_p256(&encoded.as_bytes()[1..], &data, &bytes).is_ok());
            return;
        }
    }
    panic!("deterministic corpus must contain a valid leading-zero scalar");
}

#[test]
fn valid_signatures_at_both_s_boundaries_match() {
    use p256::elliptic_curve::{bigint::U256, ops::Reduce, sec1::ToEncodedPoint};
    use p256::{FieldBytes, ProjectivePoint, Scalar};

    // With nonce k=1, choose d=(s-e)/r to construct real signatures at
    // s=1 and s=n-1. This tests acceptance, not just malformed scalar rejection.
    let data = b"DNSSEC scalar boundary known construction";
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let e = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(digest.as_ref()));
    let generator = ProjectivePoint::GENERATOR
        .to_affine()
        .to_encoded_point(false);
    let r = <Scalar as Reduce<U256>>::reduce_bytes(generator.x().unwrap());
    let inverse = Option::<Scalar>::from(r.invert()).unwrap();
    for s in [Scalar::ONE, -Scalar::ONE] {
        let d = (s - e) * inverse;
        assert_ne!(d, Scalar::ZERO);
        let public = (ProjectivePoint::GENERATOR * d)
            .to_affine()
            .to_encoded_point(false);
        let signature = Signature::from_scalars(r.to_bytes(), s.to_bytes()).unwrap();
        assert!(reference(&public.as_bytes()[1..], data, &signature.to_bytes()).is_ok());
        assert!(verify_ecdsa_p256(&public.as_bytes()[1..], data, &signature.to_bytes()).is_ok());
    }
}

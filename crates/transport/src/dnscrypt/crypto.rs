use super::*;
use curve25519_dalek::{MontgomeryPoint, traits::IsIdentity};

pub(super) fn valid_public_key(public_key: [u8; 32]) -> bool {
    // crypto_box does not reject an all-zero X25519 shared point. Check with
    // a fixed clamped scalar so this validation never handles secret material.
    // Low-order points (including noncanonical encodings) produce the identity
    // for every clamped X25519 scalar.
    !MontgomeryPoint(public_key)
        .mul_clamped([0; 32])
        .is_identity()
}

pub(super) fn checked_box(
    public_key: [u8; 32],
    secret_key: &SecretKey,
) -> Result<ChaChaBox, TransportError> {
    if !valid_public_key(public_key) {
        return Err(TransportError::InvalidDnscryptProtocol(
            "low-order X25519 public key",
        ));
    }
    Ok(ChaChaBox::new(&PublicKey::from(public_key), secret_key))
}

pub(super) fn encrypt_query(
    certificate: &DnscryptCertificate,
    client_secret: &SecretKey,
    client_nonce: [u8; 12],
    query_wire: &[u8],
) -> Result<Vec<u8>, TransportError> {
    encrypt_query_with_minimum(certificate, client_secret, client_nonce, query_wire, 0)
}

pub(super) fn encrypt_query_with_minimum(
    certificate: &DnscryptCertificate,
    client_secret: &SecretKey,
    client_nonce: [u8; 12],
    query_wire: &[u8],
    minimum_packet_length: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut random = [0];
    getrandom::fill(&mut random)
        .map_err(|_| TransportError::InvalidDnscryptProtocol("cannot generate query padding"))?;
    let minimum_plaintext = minimum_packet_length.saturating_sub(QUERY_HEADER_LENGTH + TAG_LENGTH);
    let plaintext = pad_at_least(
        query_wire,
        minimum_plaintext,
        MAX_QUERY_PLAINTEXT,
        usize::from(random[0] & 3),
    )?;
    let mut nonce = [0; 24];
    nonce[..12].copy_from_slice(&client_nonce);
    let cipher = checked_box(certificate.resolver_public_key, client_secret)?;
    let encrypted = cipher
        .encrypt(GenericArray::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| TransportError::InvalidDnscryptProtocol("query encryption failed"))?;
    let mut packet = Vec::with_capacity(QUERY_HEADER_LENGTH + encrypted.len());
    packet.extend_from_slice(&certificate.client_magic);
    packet.extend_from_slice(client_secret.public_key().as_bytes());
    packet.extend_from_slice(&client_nonce);
    packet.extend_from_slice(&encrypted);
    if packet.len() > MAX_PACKET_LENGTH {
        return Err(TransportError::MessageTooLong {
            length: packet.len(),
            maximum: MAX_PACKET_LENGTH,
        });
    }
    Ok(packet)
}

pub(super) fn decrypt_response(
    certificate: &DnscryptCertificate,
    client_secret: &SecretKey,
    client_nonce: [u8; 12],
    packet: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if packet.len() < RESPONSE_HEADER_LENGTH + TAG_LENGTH
        || packet.len() > MAX_PACKET_LENGTH
        || packet[..8] != RESOLVER_MAGIC
        || packet[8..20] != client_nonce
    {
        return Err(TransportError::InvalidDnscryptProtocol(
            "response header or client nonce is invalid",
        ));
    }
    let nonce: [u8; 24] = packet[8..32]
        .try_into()
        .map_err(|_| TransportError::InvalidDnscryptProtocol("response nonce is incomplete"))?;
    if nonce[12..] == [0; 12] {
        return Err(TransportError::InvalidDnscryptProtocol(
            "resolver nonce is all zero",
        ));
    }
    let cipher = checked_box(certificate.resolver_public_key, client_secret)?;
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), &packet[32..])
        .map_err(|_| TransportError::InvalidDnscryptProtocol("response authentication failed"))?;
    unpad(&plaintext)
}

pub(super) fn pad(
    message: &[u8],
    maximum_plaintext: usize,
    extra_blocks: usize,
) -> Result<Vec<u8>, TransportError> {
    pad_at_least(message, 0, maximum_plaintext, extra_blocks)
}

pub(super) fn pad_at_least(
    message: &[u8],
    minimum_plaintext: usize,
    maximum_plaintext: usize,
    extra_blocks: usize,
) -> Result<Vec<u8>, TransportError> {
    let minimum = message
        .len()
        .checked_add(1)
        .map(|length| length.max(minimum_plaintext))
        .ok_or(TransportError::MessageTooLong {
            length: usize::MAX,
            maximum: maximum_plaintext,
        })?;
    if minimum > maximum_plaintext {
        return Err(TransportError::MessageTooLong {
            length: minimum,
            maximum: maximum_plaintext,
        });
    }
    let minimum_padded_length = minimum
        .checked_add(63)
        .map(|length| length / 64 * 64)
        .filter(|&length| length <= maximum_plaintext)
        // Block alignment is preferred, but even a single padding delimiter
        // is valid when the packet budget cannot accommodate the next block.
        .unwrap_or(minimum);
    let available_blocks = (maximum_plaintext - minimum_padded_length) / 64;
    let padded_length = minimum_padded_length + 64 * extra_blocks.min(available_blocks);
    let mut plaintext = Vec::with_capacity(padded_length);
    plaintext.extend_from_slice(message);
    plaintext.push(0x80);
    plaintext.resize(padded_length, 0);
    Ok(plaintext)
}

pub(super) fn unpad(plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
    let delimiter = plaintext
        .iter()
        .rposition(|&octet| octet != 0)
        .filter(|&position| plaintext[position] == 0x80)
        .ok_or(TransportError::InvalidDnscryptProtocol(
            "plaintext has invalid ISO/IEC 7816-4 padding",
        ))?;
    Ok(plaintext[..delimiter].to_vec())
}

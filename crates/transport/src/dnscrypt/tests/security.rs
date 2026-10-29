use super::*;

#[test]
fn production_nonces_do_not_expose_a_stable_counter_prefix() {
    let (_, config, client_config) = configurations();
    let client = DnscryptTransport::with_client_key(client_config, bytes(65)).unwrap();
    for nonces in [
        (0..8)
            .map(|_| client.next_client_nonce().unwrap())
            .collect::<Vec<_>>(),
        (0..8)
            .map(|_| config.next_resolver_nonce().unwrap())
            .collect::<Vec<_>>(),
    ] {
        // Eight independent 96-bit nonces share a 32-bit prefix with
        // probability 2^-224. The old counter source always shared it.
        assert!(nonces.iter().any(|nonce| nonce[..4] != nonces[0][..4]));
        assert!(nonces.iter().all(|nonce| *nonce != [0; 12]));
    }
}

fn signed_certificate_with_key(public_key: [u8; 32]) -> Vec<u8> {
    let mut wire = vector_certificate().as_bytes().to_vec();
    wire[72..104].copy_from_slice(&public_key);
    let signature = SigningKey::from_bytes(&bytes(0)).sign(&wire[72..]);
    wire[8..72].copy_from_slice(&signature.to_bytes());
    wire
}

fn low_order_keys() -> Vec<[u8; 32]> {
    let mut keys = vec![[0; 32]];
    let mut one = [0; 32];
    one[0] = 1;
    keys.push(one);
    for first in [0xec, 0xed, 0xee] {
        let mut key = [0xff; 32];
        key[0] = first;
        key[31] = 0x7f;
        keys.push(key);
    }
    let aliases = keys
        .iter()
        .map(|key| {
            let mut key = *key;
            key[31] |= 0x80;
            key
        })
        .collect::<Vec<_>>();
    keys.extend(aliases);
    keys
}

#[test]
fn rejects_signed_certificates_with_low_order_resolver_keys() {
    let provider = SigningKey::from_bytes(&bytes(0)).verifying_key().to_bytes();
    for key in low_order_keys() {
        assert!(!valid_public_key(key));
        assert!(
            DnscryptCertificate::verify(&signed_certificate_with_key(key), &provider, 0x6800_0000,)
                .is_err()
        );
        assert!(DnscryptCertificate::sign(&bytes(0), key, [1; 8], 1, 1, 2,).is_err());
    }
}

#[tokio::test]
async fn forged_queries_with_low_order_client_keys_never_reach_the_handler() {
    let (_, config, _) = configurations();
    let identity = &config.identities[0];
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(EchoHandler(Arc::clone(&calls)));
    let mut plaintext = query(7).into_wire().unwrap();
    plaintext.push(0x80);
    for key in low_order_keys() {
        // These ciphertexts authenticate under the publicly computable key
        // derived from the zero shared point, even without a client secret.
        let cipher = ChaChaBox::new(&PublicKey::from(key), &SecretKey::from(bytes(33)));
        let encrypted = cipher
            .encrypt(GenericArray::from_slice(&[0; 24]), plaintext.as_slice())
            .unwrap();
        let mut packet = identity.certificate.client_magic.to_vec();
        packet.extend_from_slice(&key);
        packet.extend_from_slice(&[0; 12]);
        packet.extend_from_slice(&encrypted);
        assert!(
            serve_datagram(
                "127.0.0.1:12345".parse().unwrap(),
                &packet,
                &config,
                Arc::clone(&handler)
            )
            .await
            .is_none()
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn rejects_reserved_magic_and_ambiguous_resolver_identities() {
    let resolver = SecretKey::from(bytes(33));
    for magic in [
        RESUME_MAGIC,
        RESOLVER_MAGIC,
        [0; 8],
        [0, 0, 0, 0, 0, 0, 0, 1],
    ] {
        assert!(DnscryptCertificate::sign(
            &bytes(1), *resolver.public_key().as_bytes(), magic, 1, 1, 2,
        ).is_err());
    }
    let (name, config, _) = configurations();
    let identity = config.identities[0].clone();
    assert!(DnscryptServerConfig::new(name, vec![identity.clone(), identity]).is_err());
}

#[test]
fn minimal_padding_uses_the_full_transport_budget() {
    for maximum in [
        1,
        17,
        63,
        64,
        65,
        MAX_QUERY_PLAINTEXT,
        MAX_RESPONSE_PLAINTEXT,
    ] {
        let wire = vec![0x55; maximum - 1];
        let padded = pad(&wire, maximum, 3).unwrap();
        assert_eq!(padded.len(), maximum);
        assert_eq!(unpad(&padded).unwrap(), wire);
    }
}

#[tokio::test]
async fn minimally_padded_queries_receive_a_response_within_their_udp_budget() {
    let (_, config, _) = configurations();
    let identity = &config.identities[0];
    let client = SecretKey::from(bytes(65));
    let request = query(7);
    let mut plaintext = request.into_wire().unwrap();
    plaintext.push(0x80);
    let cipher = ChaChaBox::new(
        &PublicKey::from(identity.certificate.resolver_public_key),
        &client,
    );
    let encrypted = cipher
        .encrypt(GenericArray::from_slice(&[0; 24]), plaintext.as_slice())
        .unwrap();
    let mut packet = identity.certificate.client_magic.to_vec();
    packet.extend_from_slice(client.public_key().as_bytes());
    packet.extend_from_slice(&[0; 12]);
    packet.extend_from_slice(&encrypted);
    let response = serve_datagram(
        "127.0.0.1:12345".parse().unwrap(),
        &packet,
        &config,
        Arc::new(EchoHandler(Arc::new(AtomicUsize::new(0)))),
    )
    .await
    .unwrap();
    assert!(response.len() <= packet.len());
    let response = decrypt_response(&identity.certificate, &client, [0; 12], &response).unwrap();
    let response = Message::from_wire(&response).unwrap();
    assert!(response.headers.qr);
    assert!(same_questions(&response.questions, &request.questions));
}

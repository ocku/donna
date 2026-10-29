use std::time::{SystemTime, UNIX_EPOCH};

use dns::{IntoWire, Message, RCode, RData, Sig0Error, Sig0SigningKey, VerifiedSig0Message};

use crate::response::error_response;

pub(super) enum Sig0Authentication {
    Unsigned(Message),
    Rejected(Message),
    Authenticated {
        query: Message,
        key: Sig0SigningKey,
        request_wire: Vec<u8>,
        signature: Vec<u8>,
        inception: u32,
        expiration: u32,
    },
}

pub(super) fn unix_time_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(super) fn authenticate(
    query: Message,
    wire: &[u8],
    keys: &[Sig0SigningKey],
    now: u64,
) -> Sig0Authentication {
    let Some(request_sig) = query
        .additionals
        .last()
        .and_then(|record| match &record.rdata {
            RData::SIG(sig) if sig.is_sig0() => Some(sig),
            _ => None,
        })
    else {
        return Sig0Authentication::Unsigned(query);
    };
    let candidates = keys.iter().filter(|key| {
        let verification = key.verification_key();
        verification.name().eq_dns(&request_sig.signer_name)
            && verification.key().key_tag() == request_sig.key_tag
            && verification.key().algorithm == request_sig.algorithm
    });
    let mut last_error = None;
    for key in candidates {
        match key.verification_key().verify_request(wire, now) {
            Ok(VerifiedSig0Message { message, sig }) => {
                return Sig0Authentication::Authenticated {
                    query: message,
                    key: key.clone(),
                    request_wire: wire.to_vec(),
                    signature: sig.signature,
                    inception: sig.signature_inception,
                    expiration: sig.signature_expiration,
                };
            }
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        None
        | Some(
            Sig0Error::BadKey
            | Sig0Error::BadAlgorithm
            | Sig0Error::BadSignature
            | Sig0Error::BadTime,
        ) => Sig0Authentication::Rejected(error_response(&query, RCode::NotAuthoritative)),
        Some(_) => Sig0Authentication::Rejected(error_response(&query, RCode::FormatError)),
    }
}

pub(super) fn sign_response(
    key: &Sig0SigningKey,
    request_wire: &[u8],
    response: &mut Message,
    query: &Message,
    protocol: transport::TransportProtocol,
) -> Result<(), Sig0Error> {
    let now = unix_time_now() as u32;
    let inception = now.wrapping_sub(300);
    let expiration = now.wrapping_add(300);
    key.sign_response(response, request_wire, inception, expiration)?;
    if protocol == transport::TransportProtocol::Udp {
        let limit = query
            .edns()
            .ok()
            .flatten()
            .map_or(512, |edns| usize::from(edns.effective_udp_payload_size()))
            .min(usize::from(dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE));
        let oversized = response
            .clone()
            .into_wire()
            .map_or(true, |wire| wire.len() > limit);
        if oversized {
            let mut truncated = super::signed_response::truncated(query, response);
            key.sign_response(
                &mut truncated,
                request_wire,
                now.wrapping_sub(300),
                now.wrapping_add(300),
            )?;
            *response = truncated;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{ClassType, DomainName, Headers, QClassType, QueryType, Question};

    const VALID_PKCS8: &[u8] = &[
        48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 156, 58, 61, 68, 60, 178, 171,
        104, 83, 159, 96, 163, 246, 190, 164, 46, 68, 164, 64, 34, 239, 214, 158, 122, 111, 82, 80,
        170, 50, 90, 126, 173, 129, 33, 0, 40, 191, 220, 61, 124, 212, 177, 148, 240, 248, 32, 200,
        38, 226, 202, 169, 240, 228, 175, 220, 162, 168, 147, 131, 122, 208, 184, 21, 228, 15, 161,
        31,
    ];
    const OTHER_PKCS8: &[u8] = &[
        48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 24, 100, 104, 52, 205, 219, 127,
        140, 33, 232, 198, 32, 222, 16, 215, 137, 127, 79, 74, 178, 39, 37, 99, 198, 125, 94, 205,
        164, 164, 8, 219, 107, 129, 33, 0, 242, 103, 121, 209, 128, 20, 108, 162, 89, 219, 159,
        122, 1, 216, 180, 15, 103, 136, 64, 94, 36, 48, 149, 57, 204, 95, 50, 185, 240, 133, 65,
        120,
    ];

    fn name() -> DomainName {
        DomainName::from_dotted("host.example.").unwrap()
    }

    fn signing_key(pkcs8: &[u8], flags: u16) -> Sig0SigningKey {
        Sig0SigningKey::from_ed25519_pkcs8(name(), flags, 3, pkcs8).unwrap()
    }

    #[test]
    fn authentication_tries_every_colliding_identity_candidate_and_retains_the_match() {
        let valid = signing_key(VALID_PKCS8, 0);
        let expected_tag = valid.verification_key().key().key_tag();

        let other_probe = signing_key(OTHER_PKCS8, 0);
        let mut other_public = other_probe.verification_key().key().clone();
        let colliding_flags = (0..=u16::MAX)
            .find(|flags| {
                other_public.flags = *flags;
                other_public.key_tag() == expected_tag
            })
            .expect("KEY flags span every possible key-tag value");
        let colliding = signing_key(OTHER_PKCS8, colliding_flags);
        assert_eq!(colliding.verification_key().key().key_tag(), expected_tag);

        let mut request = Message::builder()
            .headers(Headers::default())
            .questions([Question {
                qname: DomainName::from_dotted("example.").unwrap(),
                qtype: QueryType::SOA,
                qclass: QClassType::Class(ClassType::IN),
            }])
            .build()
            .unwrap();
        valid.sign_request(&mut request, 100, 200).unwrap();
        let wire = request.into_wire().unwrap();

        let Sig0Authentication::Authenticated { key, query, .. } =
            authenticate(request, &wire, &[colliding, valid.clone()], 150)
        else {
            panic!("the second colliding key should authenticate the request");
        };
        assert!(query.additionals.is_empty());
        assert_eq!(
            key.verification_key().key().public_key,
            valid.verification_key().key().public_key
        );
    }
}

//! RFC 8945 MAC primitives; protocol truncation policy remains with `TsigKey`.
use hmac::{Hmac, Mac};

use crate::TsigAlgorithm;

type Sha1Mac = Hmac<sha1::Sha1>;
use crate::protocol::mac::Sha256Mac;

pub(super) fn calculate(algorithm: TsigAlgorithm, secret: &[u8], input: &[u8]) -> Vec<u8> {
    match algorithm {
        TsigAlgorithm::HmacSha1 => {
            let mut mac = Sha1Mac::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(input);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlgorithm::HmacSha256 => {
            let mut mac = Sha256Mac::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(input);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

pub(super) fn verify(algorithm: TsigAlgorithm, secret: &[u8], input: &[u8], tag: &[u8]) -> bool {
    match algorithm {
        TsigAlgorithm::HmacSha1 => {
            let mut mac = Sha1Mac::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(input);
            mac.verify_truncated_left(tag).is_ok()
        }
        TsigAlgorithm::HmacSha256 => {
            let mut mac = Sha256Mac::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(input);
            mac.verify_truncated_left(tag).is_ok()
        }
    }
}

#[cfg(test)]
mod tests;

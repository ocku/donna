//! One bounded mathematical signature result per immutable authenticated key set.
//! This stores no trust decision, time interval or authenticated TTL.
use std::sync::Mutex;

use crate::RrsigVerificationError;

#[derive(Debug, Default)]
pub(crate) struct SuccessfulSignatureCache(Mutex<Option<VerifiedSignature>>);

#[derive(Debug)]
struct VerifiedSignature {
    algorithm: u8,
    key: Box<[u8]>,
    data: Box<[u8]>,
    signature: Box<[u8]>,
}

impl SuccessfulSignatureCache {
    #[cfg(test)]
    pub(crate) fn is_populated(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_some()
    }

    #[cfg(test)]
    pub(crate) fn contains_exact(
        &self,
        algorithm: u8,
        key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .is_some_and(|entry| {
                entry.algorithm == algorithm
                    && entry.key.as_ref() == key
                    && entry.data.as_ref() == data
                    && entry.signature.as_ref() == signature
            })
    }

    pub(crate) fn verify(
        &self,
        algorithm: u8,
        key: &[u8],
        data: &[u8],
        signature: &[u8],
        verify: impl FnOnce() -> Result<(), RrsigVerificationError>,
    ) -> Result<(), RrsigVerificationError> {
        // Large/irregular inputs retain the ordinary verifier. One entry holds
        // at most 2560 octets, independent of the number of queries or owners.
        if key.len() > 1024 || data.len() > 1024 || signature.len() > 512 {
            return verify();
        }
        {
            let entry = self.0.lock().unwrap_or_else(|error| error.into_inner());
            if entry.as_ref().is_some_and(|entry| {
                entry.algorithm == algorithm
                    && entry.key.as_ref() == key
                    && entry.data.as_ref() == data
                    && entry.signature.as_ref() == signature
            }) {
                return Ok(());
            }
        }
        // Neither curve/RSA work nor allocation holds the cache mutex. Never
        // retain errors; candidate-key/signature order and error precedence stay.
        verify()?;
        let entry = VerifiedSignature {
            algorithm,
            key: key.into(),
            data: data.into(),
            signature: signature.into(),
        };
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = Some(entry);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn oversized_inputs_and_failures_never_enter_the_success_slot() {
        let cache = SuccessfulSignatureCache::default();
        let calls = Cell::new(0);
        let verify = || {
            calls.set(calls.get() + 1);
            Ok(())
        };
        for (key, data, signature) in [
            (vec![0; 1025], vec![0], vec![0]),
            (vec![0], vec![0; 1025], vec![0]),
            (vec![0], vec![0], vec![0; 513]),
        ] {
            for _ in 0..2 {
                cache.verify(13, &key, &data, &signature, verify).unwrap();
                assert!(cache.0.lock().unwrap().is_none());
            }
        }
        assert_eq!(calls.get(), 6);
        for _ in 0..2 {
            assert!(
                cache
                    .verify(13, &[1], &[2], &[3], || Err(
                        RrsigVerificationError::BadSignature
                    ))
                    .is_err()
            );
            assert!(cache.0.lock().unwrap().is_none());
        }
    }
}

use std::fmt;

use crate::{DomainName, IntoWire, Message, RCode, RData, Tsig, TsigAlgorithm, TsigErrorCode};

use super::{
    TsigAuthenticationError, TsigRequestAuthentication, VerifiedTsigMessage,
    wire::{SplitTsig, check_time, ensure_no_tsig, split_tsig, standard_mac_input, tsig_record},
};

/// A shared secret and its single associated TSIG algorithm.
///
/// Debug output deliberately omits the secret bytes.
#[derive(Clone)]
pub struct TsigKey {
    pub(super) name: DomainName,
    pub(super) algorithm: TsigAlgorithm,
    secret: Vec<u8>,
    pub(super) minimum_mac_len: usize,
}

impl fmt::Debug for TsigKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"[REDACTED]")
            .field("minimum_mac_len", &self.minimum_mac_len)
            .finish()
    }
}

impl TsigKey {
    /// Creates a key using the RFC protocol minimum truncation policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret is empty.
    pub fn new(
        name: DomainName,
        algorithm: TsigAlgorithm,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Self, TsigAuthenticationError> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(TsigAuthenticationError::EmptySecret);
        }
        Ok(Self {
            name,
            algorithm,
            secret,
            minimum_mac_len: algorithm.protocol_minimum_mac_len(),
        })
    }

    /// Applies a stricter accepted-MAC policy for this key.
    ///
    /// # Errors
    ///
    /// Returns an error below the protocol minimum or above the hash output.
    pub fn with_minimum_mac_len(mut self, minimum: usize) -> Result<Self, TsigAuthenticationError> {
        if minimum < self.algorithm.protocol_minimum_mac_len()
            || minimum > self.algorithm.output_len()
        {
            return Err(TsigAuthenticationError::InvalidMacLength {
                length: minimum,
                minimum: self.algorithm.protocol_minimum_mac_len(),
                maximum: self.algorithm.output_len(),
            });
        }
        self.minimum_mac_len = minimum;
        Ok(self)
    }

    /// Returns the case-preserving key name.
    pub fn name(&self) -> &DomainName {
        &self.name
    }

    /// Returns the key's registered algorithm.
    pub const fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }

    /// Signs a request and appends its sole, final TSIG additional record.
    ///
    /// `mac_len` selects a permitted leading truncation; `None` uses the full
    /// keyed hash output. The returned bytes are the transmitted MAC and must
    /// be retained while awaiting the response.
    ///
    /// # Errors
    ///
    /// Returns an error for a response message, an existing TSIG, an invalid
    /// timestamp or truncation, or a message that cannot be encoded.
    pub fn sign_request(
        &self,
        message: &mut Message,
        time_signed: u64,
        fudge: u16,
        mac_len: Option<usize>,
    ) -> Result<Vec<u8>, TsigAuthenticationError> {
        if message.headers.qr {
            return Err(TsigAuthenticationError::WrongDirection);
        }
        self.sign_standard(
            message,
            None,
            message.headers.id,
            time_signed,
            fudge,
            TsigErrorCode::NoError,
            Vec::new(),
            mac_len,
            None,
        )
    }

    /// Signs a response using the validated request MAC.
    ///
    /// Ordinary responses use `NoError` and empty Other Data. A BADTIME
    /// response uses the request's Time Signed value here and the server's
    /// six-octet current time in `other_data`.
    ///
    /// # Errors
    ///
    /// Returns an error for a request message, invalid error data, an existing
    /// TSIG, or a message that cannot be represented.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_response(
        &self,
        message: &mut Message,
        request_mac: &[u8],
        original_id: u16,
        time_signed: u64,
        fudge: u16,
        error: TsigErrorCode,
        other_data: Vec<u8>,
        mac_len: Option<usize>,
    ) -> Result<Vec<u8>, TsigAuthenticationError> {
        self.sign_response_context(
            message,
            None,
            request_mac,
            original_id,
            time_signed,
            fudge,
            error,
            other_data,
            mac_len,
        )
    }

    /// Signs an IXFR response using explicit transfer context.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_response_ixfr(
        &self,
        message: &mut Message,
        question: &crate::Question,
        request_mac: &[u8],
        original_id: u16,
        time_signed: u64,
        fudge: u16,
        error: TsigErrorCode,
        other_data: Vec<u8>,
        mac_len: Option<usize>,
    ) -> Result<Vec<u8>, TsigAuthenticationError> {
        self.sign_response_context(
            message,
            Some(question),
            request_mac,
            original_id,
            time_signed,
            fudge,
            error,
            other_data,
            mac_len,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn sign_response_context(
        &self,
        message: &mut Message,
        question: Option<&crate::Question>,
        request_mac: &[u8],
        original_id: u16,
        time_signed: u64,
        fudge: u16,
        error: TsigErrorCode,
        other_data: Vec<u8>,
        mac_len: Option<usize>,
    ) -> Result<Vec<u8>, TsigAuthenticationError> {
        if !message.headers.qr {
            return Err(TsigAuthenticationError::WrongDirection);
        }
        if matches!(error, TsigErrorCode::BadKey | TsigErrorCode::BadSignature) {
            return Err(TsigAuthenticationError::ErrorMustBeUnsigned { error });
        }
        if (error == TsigErrorCode::BadTime && other_data.len() != 6)
            || (error != TsigErrorCode::BadTime && !other_data.is_empty())
        {
            return Err(TsigAuthenticationError::InvalidOtherData);
        }
        let response_mac_len = mac_len.unwrap_or_else(|| self.algorithm.output_len());
        if response_mac_len < request_mac.len() {
            return Err(TsigAuthenticationError::BadTruncation {
                length: response_mac_len,
                minimum: request_mac.len(),
            });
        }
        self.sign_standard(
            message,
            Some(request_mac),
            original_id,
            time_signed,
            fudge,
            error,
            other_data,
            Some(response_mac_len),
            question,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_standard(
        &self,
        message: &mut Message,
        prior_mac: Option<&[u8]>,
        original_id: u16,
        time_signed: u64,
        fudge: u16,
        error: TsigErrorCode,
        other_data: Vec<u8>,
        mac_len: Option<usize>,
        question: Option<&crate::Question>,
    ) -> Result<Vec<u8>, TsigAuthenticationError> {
        ensure_no_tsig(message)?;
        if let Some(mac) = prior_mac {
            self.check_protocol_mac_len(mac.len())?;
        }
        if time_signed > Tsig::MAX_TIME_SIGNED {
            return Err(TsigAuthenticationError::TimeTooLarge { value: time_signed });
        }
        let mac_len = self.signing_mac_len(mac_len)?;
        let mut unsigned = question
            .map_or_else(|| message.into_wire(), |q| message.into_wire_ixfr(q))
            .map_err(TsigAuthenticationError::Wire)?;
        unsigned[..2].copy_from_slice(&original_id.to_be_bytes());
        let mut tsig = Tsig {
            algorithm: self.algorithm.name(),
            time_signed,
            fudge,
            mac: Vec::new(),
            original_id,
            error,
            other_data,
        };
        let record = tsig_record(self.name.clone(), tsig.clone());
        let input = standard_mac_input(prior_mac, &unsigned, &record);
        tsig.mac = self.calculate(&input)[..mac_len].to_vec();
        let mac = tsig.mac.clone();
        message
            .additionals
            .push(tsig_record(self.name.clone(), tsig));
        Ok(mac)
    }

    /// Verifies and removes the TSIG from an exact request wire image.
    ///
    /// # Errors
    ///
    /// Checks key and algorithm, MAC, validity interval, and local truncation
    /// policy in RFC 8945 order.
    pub fn verify_request(
        &self,
        wire: &[u8],
        now: u64,
    ) -> Result<VerifiedTsigMessage, TsigAuthenticationError> {
        match self.authenticate_request(wire, now)? {
            TsigRequestAuthentication::Verified(message) => Ok(message),
            TsigRequestAuthentication::BadTime(_) => Err(TsigAuthenticationError::BadTime),
            TsigRequestAuthentication::BadTruncation(message) => {
                Err(TsigAuthenticationError::BadTruncation {
                    length: message.mac.len(),
                    minimum: self.minimum_mac_len,
                })
            }
        }
    }

    /// Authenticates a request while retaining a valid request MAC when its
    /// time or local truncation policy requires a signed error response.
    ///
    /// # Errors
    ///
    /// Returns an error when placement, key, algorithm, protocol MAC length,
    /// or signature verification fails.
    pub fn authenticate_request(
        &self,
        wire: &[u8],
        now: u64,
    ) -> Result<TsigRequestAuthentication, TsigAuthenticationError> {
        let split = split_tsig(wire)?;
        if split.message.headers.qr {
            return Err(TsigAuthenticationError::WrongDirection);
        }
        let verified = self.verify_standard_mac(split, None)?;
        if check_time(&verified.tsig, now).is_err() {
            return Ok(TsigRequestAuthentication::BadTime(verified));
        }
        if verified.mac.len() < self.minimum_mac_len {
            return Ok(TsigRequestAuthentication::BadTruncation(verified));
        }
        Ok(TsigRequestAuthentication::Verified(verified))
    }

    /// Verifies and removes a response TSIG using its request MAC.
    ///
    /// Unsigned BADKEY/BADSIG error responses are reported distinctly and are
    /// never returned as authenticated messages.
    pub fn verify_response(
        &self,
        wire: &[u8],
        request_mac: &[u8],
        now: u64,
    ) -> Result<VerifiedTsigMessage, TsigAuthenticationError> {
        let split = split_tsig(wire)?;
        if !split.message.headers.qr {
            return Err(TsigAuthenticationError::WrongDirection);
        }
        self.verify_standard(split, Some(request_mac), now)
    }

    fn verify_standard(
        &self,
        split: SplitTsig,
        prior_mac: Option<&[u8]>,
        now: u64,
    ) -> Result<VerifiedTsigMessage, TsigAuthenticationError> {
        let verified = self.verify_standard_mac(split, prior_mac)?;
        check_time(&verified.tsig, now)?;
        if verified.mac.len() < self.minimum_mac_len {
            return Err(TsigAuthenticationError::BadTruncation {
                length: verified.mac.len(),
                minimum: self.minimum_mac_len,
            });
        }
        Ok(verified)
    }

    fn verify_standard_mac(
        &self,
        mut split: SplitTsig,
        prior_mac: Option<&[u8]>,
    ) -> Result<VerifiedTsigMessage, TsigAuthenticationError> {
        let RData::TSIG(tsig) = &split.record.rdata else {
            unreachable!("split_tsig requires structured TSIG RDATA")
        };
        self.check_key_and_algorithm(&split.record.name, &tsig.algorithm)?;
        if tsig.mac.is_empty()
            && split.message.headers.qr
            && split.message.headers.rcode == RCode::NotAuthoritative
            && matches!(
                tsig.error,
                TsigErrorCode::BadKey | TsigErrorCode::BadSignature
            )
        {
            return Err(TsigAuthenticationError::UnsignedError { error: tsig.error });
        }
        self.check_protocol_mac_len(tsig.mac.len())?;
        let input = standard_mac_input(prior_mac, &split.unsigned_wire, &split.record);
        if !self.verify_mac(&input, &tsig.mac) {
            return Err(TsigAuthenticationError::BadSignature);
        }
        let mac = tsig.mac.clone();
        let tsig = tsig.clone();
        split.message.additionals.pop();
        Ok(VerifiedTsigMessage {
            message: split.message,
            tsig,
            mac,
        })
    }

    pub(super) fn check_key_and_algorithm(
        &self,
        owner: &DomainName,
        algorithm: &DomainName,
    ) -> Result<(), TsigAuthenticationError> {
        if !owner.eq_dns(&self.name) {
            return Err(TsigAuthenticationError::BadKey);
        }
        if !algorithm.eq_dns(&self.algorithm.name()) {
            return Err(TsigAuthenticationError::BadAlgorithm);
        }
        Ok(())
    }

    pub(super) fn signing_mac_len(
        &self,
        requested: Option<usize>,
    ) -> Result<usize, TsigAuthenticationError> {
        let length = requested.unwrap_or_else(|| self.algorithm.output_len());
        if length < self.algorithm.protocol_minimum_mac_len()
            || length > self.algorithm.output_len()
        {
            return Err(TsigAuthenticationError::InvalidMacLength {
                length,
                minimum: self.algorithm.protocol_minimum_mac_len(),
                maximum: self.algorithm.output_len(),
            });
        }
        Ok(length)
    }

    pub(super) fn check_protocol_mac_len(
        &self,
        length: usize,
    ) -> Result<(), TsigAuthenticationError> {
        if length < self.algorithm.protocol_minimum_mac_len()
            || length > self.algorithm.output_len()
        {
            return Err(TsigAuthenticationError::InvalidMacLength {
                length,
                minimum: self.algorithm.protocol_minimum_mac_len(),
                maximum: self.algorithm.output_len(),
            });
        }
        Ok(())
    }

    pub(super) fn calculate(&self, input: &[u8]) -> Vec<u8> {
        super::mac::calculate(self.algorithm, &self.secret, input)
    }

    pub(super) fn verify_mac(&self, input: &[u8], tag: &[u8]) -> bool {
        super::mac::verify(self.algorithm, &self.secret, input, tag)
    }
}

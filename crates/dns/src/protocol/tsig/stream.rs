use crate::{FromWire, IntoWire, Message, RData, RecordType, Tsig, TsigErrorCode};

use super::{
    TsigAuthenticationError, TsigKey,
    wire::{check_time, ensure_no_tsig, split_tsig, stream_mac_input, tsig_record},
};

/// Signs every response in a multi-message DNS stream.
///
/// The first response uses the request-MAC construction; later responses use
/// RFC 8945's running prior-MAC and timers-only construction.
#[derive(Debug, Clone)]
pub struct TsigStreamSigner {
    key: TsigKey,
    request_mac: Vec<u8>,
    prior_mac: Option<Vec<u8>>,
}

impl TsigStreamSigner {
    /// Starts a response stream chained to a validated request MAC.
    pub fn new(key: TsigKey, request_mac: Vec<u8>) -> Self {
        Self {
            key,
            request_mac,
            prior_mac: None,
        }
    }

    /// Signs the next response. Generated streams place TSIG on every message.
    ///
    /// # Errors
    ///
    /// Returns an error for a request, existing TSIG, invalid time or
    /// truncation, or unencodable response.
    pub fn sign_next(
        &mut self,
        message: &mut Message,
        original_id: u16,
        time_signed: u64,
        fudge: u16,
        mac_len: Option<usize>,
    ) -> Result<Vec<u8>, TsigAuthenticationError> {
        self.sign_next_context(message, None, original_id, time_signed, fudge, mac_len)
    }

    /// Signs the next IXFR frame with explicit transfer context.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_next_ixfr(
        &mut self,
        message: &mut Message,
        question: &crate::Question,
        original_id: u16,
        time_signed: u64,
        fudge: u16,
        mac_len: Option<usize>,
    ) -> Result<Vec<u8>, TsigAuthenticationError> {
        self.sign_next_context(
            message,
            Some(question),
            original_id,
            time_signed,
            fudge,
            mac_len,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_next_context(
        &mut self,
        message: &mut Message,
        question: Option<&crate::Question>,
        original_id: u16,
        time_signed: u64,
        fudge: u16,
        mac_len: Option<usize>,
    ) -> Result<Vec<u8>, TsigAuthenticationError> {
        if self.prior_mac.is_none() {
            let mac = self.key.sign_response_context(
                message,
                question,
                &self.request_mac,
                original_id,
                time_signed,
                fudge,
                TsigErrorCode::NoError,
                Vec::new(),
                mac_len,
            )?;
            self.prior_mac = Some(mac.clone());
            return Ok(mac);
        }
        if !message.headers.qr {
            return Err(TsigAuthenticationError::WrongDirection);
        }
        ensure_no_tsig(message)?;
        if time_signed > Tsig::MAX_TIME_SIGNED {
            return Err(TsigAuthenticationError::TimeTooLarge { value: time_signed });
        }
        let mac_len = self.key.signing_mac_len(mac_len)?;
        let prior = self.prior_mac.as_deref().expect("checked above");
        if mac_len < prior.len() {
            return Err(TsigAuthenticationError::BadTruncation {
                length: mac_len,
                minimum: prior.len(),
            });
        }
        let mut unsigned = question
            .map_or_else(|| message.into_wire(), |q| message.into_wire_ixfr(q))
            .map_err(TsigAuthenticationError::Wire)?;
        unsigned[..2].copy_from_slice(&original_id.to_be_bytes());
        let mut tsig = Tsig {
            algorithm: self.key.algorithm.name(),
            time_signed,
            fudge,
            mac: Vec::new(),
            original_id,
            error: TsigErrorCode::NoError,
            other_data: Vec::new(),
        };
        let input = stream_mac_input(prior, &[], &unsigned, &tsig);
        tsig.mac = self.key.calculate(&input)[..mac_len].to_vec();
        let mac = tsig.mac.clone();
        message
            .additionals
            .push(tsig_record(self.key.name.clone(), tsig));
        self.prior_mac = Some(mac.clone());
        Ok(mac)
    }
}

/// Verifies a multi-message response and buffers unsigned intermediates until
/// a later running MAC authenticates them.
#[derive(Debug, Clone)]
pub struct TsigStreamVerifier {
    key: TsigKey,
    request_mac: Vec<u8>,
    prior_mac: Option<Vec<u8>>,
    pending_wire: Vec<u8>,
    pending_messages: Vec<Message>,
    last_time_signed: Option<u64>,
}

impl TsigStreamVerifier {
    /// Starts verification chained to the MAC of the signed request.
    pub fn new(key: TsigKey, request_mac: Vec<u8>) -> Self {
        Self {
            key,
            request_mac,
            prior_mac: None,
            pending_wire: Vec::new(),
            pending_messages: Vec::new(),
            last_time_signed: None,
        }
    }

    /// Verifies one exact response frame.
    ///
    /// Returns `None` for an accepted unsigned intermediary. Such messages are
    /// not exposed until a later TSIG authenticates the entire pending batch.
    /// The first and final frames must be signed; at most 99 unsigned frames
    /// may occur between TSIG records.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing required TSIG, a broken chain, invalid
    /// MAC/time/truncation, or a malformed DNS message.
    pub fn verify_next(
        &mut self,
        wire: &[u8],
        now: u64,
        final_message: bool,
    ) -> Result<Option<VerifiedTsigBatch>, TsigAuthenticationError> {
        if self.prior_mac.is_none() {
            let verified = self.key.verify_response(wire, &self.request_mac, now)?;
            self.prior_mac = Some(verified.mac.clone());
            self.last_time_signed = Some(verified.tsig.time_signed);
            return Ok(Some(VerifiedTsigBatch {
                messages: vec![verified.message],
                tsig: verified.tsig,
                mac: verified.mac,
            }));
        }

        let message = Message::from_wire(wire).map_err(TsigAuthenticationError::Wire)?;
        let has_tsig = message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
            .any(|record| record.rtype == RecordType::TSIG);
        if !has_tsig {
            if final_message {
                return Err(TsigAuthenticationError::MissingTsig);
            }
            if self.pending_messages.len() == 99 {
                return Err(TsigAuthenticationError::TooManyUnsignedMessages);
            }
            self.pending_wire.extend_from_slice(wire);
            self.pending_messages.push(message);
            return Ok(None);
        }

        let mut split = split_tsig(wire)?;
        if !split.message.headers.qr {
            return Err(TsigAuthenticationError::WrongDirection);
        }
        let RData::TSIG(tsig) = &split.record.rdata else {
            unreachable!("split_tsig requires structured TSIG RDATA")
        };
        if self
            .last_time_signed
            .is_some_and(|previous| tsig.time_signed < previous)
        {
            return Err(TsigAuthenticationError::TimeRegression {
                previous: self.last_time_signed.expect("checked above"),
                current: tsig.time_signed,
            });
        }
        self.key
            .check_key_and_algorithm(&split.record.name, &tsig.algorithm)?;
        self.key.check_protocol_mac_len(tsig.mac.len())?;
        let prior = self.prior_mac.as_deref().expect("checked above");
        let input = stream_mac_input(prior, &self.pending_wire, &split.unsigned_wire, tsig);
        if !self.key.verify_mac(&input, &tsig.mac) {
            return Err(TsigAuthenticationError::BadSignature);
        }
        check_time(tsig, now)?;
        if tsig.mac.len() < self.key.minimum_mac_len {
            return Err(TsigAuthenticationError::BadTruncation {
                length: tsig.mac.len(),
                minimum: self.key.minimum_mac_len,
            });
        }

        let mac = tsig.mac.clone();
        let tsig = tsig.clone();
        split.message.additionals.pop();
        let mut messages = std::mem::take(&mut self.pending_messages);
        messages.push(split.message);
        self.pending_wire.clear();
        self.prior_mac = Some(mac.clone());
        self.last_time_signed = Some(tsig.time_signed);
        Ok(Some(VerifiedTsigBatch {
            messages,
            tsig,
            mac,
        }))
    }
}

/// One or more stream messages authenticated by the most recent TSIG.
#[derive(Debug, Clone)]
pub struct VerifiedTsigBatch {
    /// Messages in transmission order, each with TSIG removed.
    pub messages: Vec<Message>,
    /// The TSIG that authenticated the batch.
    pub tsig: Tsig,
    /// The running MAC for the next stream batch.
    pub mac: Vec<u8>,
}

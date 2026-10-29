use std::time::Duration;

use crate::{Message, RCode, RData, ResourceRecord, Tsig, TsigErrorCode};

mod error;
mod key;
mod mac;
mod stream;
mod wire;

pub use error::TsigAuthenticationError;
pub use key::TsigKey;
pub use stream::{TsigStreamSigner, TsigStreamVerifier, VerifiedTsigBatch};

use wire::{ensure_no_tsig, tsig_record};

/// A DNS message whose TSIG has been authenticated and removed.
#[derive(Debug, Clone)]
pub struct VerifiedTsigMessage {
    /// The semantic DNS message without its transaction-only TSIG RR.
    pub message: Message,
    /// The authenticated TSIG fields.
    pub tsig: Tsig,
    /// The received MAC retained for response or stream chaining.
    pub mac: Vec<u8>,
}

/// Result of authenticating a request MAC before server response policy.
#[derive(Debug, Clone)]
pub enum TsigRequestAuthentication {
    /// The request satisfies its time window and local MAC-length policy.
    Verified(VerifiedTsigMessage),
    /// The MAC is valid but the request is outside its permitted time window.
    BadTime(VerifiedTsigMessage),
    /// The MAC is valid but is shorter than the receiver's configured policy.
    BadTruncation(VerifiedTsigMessage),
}

/// Appends an unsigned BADKEY or BADSIG TSIG to an error response.
///
/// The request record supplies the key name, algorithm, original ID, and
/// fudge value that let the requester associate the unauthenticated error.
///
/// # Errors
///
/// Returns an error unless `response` is a response without an existing TSIG,
/// `request_record` is TSIG, and `error` is BADKEY or BADSIG.
pub fn append_unsigned_tsig_error(
    response: &mut Message,
    request_record: &ResourceRecord,
    time_signed: u64,
    error: TsigErrorCode,
) -> Result<(), TsigAuthenticationError> {
    if !response.headers.qr {
        return Err(TsigAuthenticationError::WrongDirection);
    }
    ensure_no_tsig(response)?;
    if !matches!(error, TsigErrorCode::BadKey | TsigErrorCode::BadSignature) {
        return Err(TsigAuthenticationError::ErrorMustBeUnsigned { error });
    }
    if time_signed > Tsig::MAX_TIME_SIGNED {
        return Err(TsigAuthenticationError::TimeTooLarge { value: time_signed });
    }
    let RData::TSIG(request_tsig) = &request_record.rdata else {
        return Err(TsigAuthenticationError::InvalidPlacement);
    };
    response.headers.rcode = RCode::NotAuthoritative;
    response.additionals.push(tsig_record(
        request_record.name.clone(),
        Tsig {
            algorithm: request_tsig.algorithm.clone(),
            time_signed,
            fudge: request_tsig.fudge,
            mac: Vec::new(),
            original_id: request_tsig.original_id,
            error,
            other_data: Vec::new(),
        },
    ));
    Ok(())
}

/// Converts a duration since the Unix epoch to TSIG's 48-bit second count.
///
/// # Errors
///
/// Returns an error if the duration exceeds the wire field.
pub fn tsig_time_from_unix_duration(duration: Duration) -> Result<u64, TsigAuthenticationError> {
    let value = duration.as_secs();
    if value > Tsig::MAX_TIME_SIGNED {
        Err(TsigAuthenticationError::TimeTooLarge { value })
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests;

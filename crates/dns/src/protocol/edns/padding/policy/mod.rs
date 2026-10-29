use std::fmt;

use crate::wire::WireError;
use crate::{EdnsMessageError, IntoWire, Message, RecordType, RecordValidationError};

/// RFC 8467's recommended block size for encrypted DNS queries.
pub const RECOMMENDED_QUERY_PADDING_BLOCK_SIZE: usize = 128;

/// RFC 8467's recommended block size for encrypted DNS responses.
pub const RECOMMENDED_RESPONSE_PADDING_BLOCK_SIZE: usize = 468;

const MAX_DNS_MESSAGE_OCTETS: usize = u16::MAX as usize;

/// Describes how applying an RFC 8467 padding policy changed a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingOutcome {
    /// A response was left alone because its request did not contain Padding.
    NotRequested,
    /// An EDNS Padding option was added to the message.
    Padded {
        /// Number of octets in the Padding option's data field.
        padding_octets: u16,
        /// Final DNS message length, excluding any TCP length prefix.
        message_octets: usize,
        /// Whether the final length is a multiple of the requested block size.
        ///
        /// This is false only when the size ceiling permits a zero-length
        /// Padding option but not the next complete block.
        block_aligned: bool,
    },
    /// Padding was omitted because fewer than four octets remained.
    ///
    /// Four octets are needed even for a zero-length EDNS option. RFC 8467
    /// permits its otherwise-disallowed No Padding policy in this case.
    OmittedInsufficientSpace {
        /// Unpadded DNS message length, excluding any TCP length prefix.
        message_octets: usize,
    },
}

/// A message cannot be padded according to an RFC 8467 block policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingPolicyError {
    /// A query-padding operation was given a response.
    ExpectedQuery,
    /// A response-padding operation was given a query.
    ExpectedResponse,
    /// The message has no OPT record in which to place Padding.
    MissingEdns,
    /// The block size was zero or larger than a DNS message can be.
    InvalidBlockSize {
        /// Contains the rejected block size.
        block_size: usize,
    },
    /// The unpadded message already exceeds the caller's size ceiling.
    MessageTooLarge {
        /// Contains the unpadded DNS message length.
        message_octets: usize,
        /// Contains the caller-provided maximum DNS message length.
        maximum_message_octets: usize,
    },
    /// EDNS placement, cardinality, or fixed fields are invalid.
    InvalidEdns(EdnsMessageError),
    /// A known EDNS option is malformed or Padding occurs more than once.
    InvalidEdnsOptions(RecordValidationError),
    /// The message could not be encoded before or after padding.
    Wire(WireError),
}

impl fmt::Display for PaddingPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedQuery => f.write_str("padding operation requires a DNS query"),
            Self::ExpectedResponse => f.write_str("padding operation requires a DNS response"),
            Self::MissingEdns => f.write_str("message has no EDNS OPT record for Padding"),
            Self::InvalidBlockSize { block_size } => write!(
                f,
                "padding block size {block_size} is outside the DNS message range"
            ),
            Self::MessageTooLarge {
                message_octets,
                maximum_message_octets,
            } => write!(
                f,
                concat!(
                    "unpadded DNS message length {} exceeds padding limit ",
                    "{}",
                ),
                message_octets, maximum_message_octets,
            ),
            Self::InvalidEdns(error) => write!(f, "cannot apply padding to invalid EDNS: {error}"),
            Self::InvalidEdnsOptions(error) => {
                write!(f, "cannot apply padding with invalid EDNS options: {error}")
            }
            Self::Wire(error) => write!(f, "cannot encode message while applying padding: {error}"),
        }
    }
}

impl std::error::Error for PaddingPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEdns(error) => Some(error),
            Self::InvalidEdnsOptions(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::ExpectedQuery
            | Self::ExpectedResponse
            | Self::MissingEdns
            | Self::InvalidBlockSize { .. }
            | Self::MessageTooLarge { .. } => None,
        }
    }
}

impl From<EdnsMessageError> for PaddingPolicyError {
    fn from(error: EdnsMessageError) -> Self {
        Self::InvalidEdns(error)
    }
}

impl From<RecordValidationError> for PaddingPolicyError {
    fn from(error: RecordValidationError) -> Self {
        Self::InvalidEdnsOptions(error)
    }
}

impl From<WireError> for PaddingPolicyError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl Message {
    /// Pads a query for an encrypted DNS transport using RFC 8467's
    /// recommended 128-octet block size.
    ///
    /// `maximum_message_octets` is the largest DNS message the transport may
    /// carry. It excludes TCP's two-octet length field. The query's effective
    /// EDNS UDP payload size is also enforced, even when the transport limit is
    /// larger. The message must already contain an OPT record so its EDNS
    /// payload size and any other options remain caller-controlled.
    ///
    /// # Errors
    ///
    /// Returns an error if this is a response, if EDNS is missing or invalid,
    /// if the unpadded message exceeds the size ceiling, or if encoding fails.
    pub fn pad_query_for_encrypted_transport(
        &mut self,
        maximum_message_octets: usize,
    ) -> Result<PaddingOutcome, PaddingPolicyError> {
        if self.headers.qr {
            return Err(PaddingPolicyError::ExpectedQuery);
        }
        self.pad_to_block_size_for_encrypted_transport(
            RECOMMENDED_QUERY_PADDING_BLOCK_SIZE,
            maximum_message_octets,
        )
    }

    /// Pads a response to a padded query for an encrypted DNS transport.
    ///
    /// When `request` includes the EDNS Padding option, this adds Padding to
    /// the response and targets RFC 8467's recommended 468-octet block size.
    /// An unpadded request leaves the response unchanged. The size passed here
    /// is a DNS message limit and therefore excludes TCP's length field.
    ///
    /// # Errors
    ///
    /// Returns an error if the message directions are wrong, either message's
    /// EDNS is invalid, a required response OPT record is absent, the unpadded
    /// response exceeds the ceiling, or encoding fails.
    pub fn pad_response_for_encrypted_transport(
        &mut self,
        request: &Message,
        maximum_message_octets: usize,
    ) -> Result<PaddingOutcome, PaddingPolicyError> {
        if !self.headers.qr {
            return Err(PaddingPolicyError::ExpectedResponse);
        }
        if request.headers.qr {
            return Err(PaddingPolicyError::ExpectedQuery);
        }
        let request_edns = request.edns()?;
        if let Some(edns) = &request_edns {
            edns.validate_options()?;
        }
        let requested = request_edns
            .as_ref()
            .is_some_and(|edns| edns.padding().is_some());
        if !requested {
            return Ok(PaddingOutcome::NotRequested);
        }
        let requestor_maximum = usize::from(
            request_edns
                .expect("a Padding option requires an OPT record")
                .effective_udp_payload_size(),
        );
        self.pad_to_block_size_for_encrypted_transport(
            RECOMMENDED_RESPONSE_PADDING_BLOCK_SIZE,
            maximum_message_octets.min(requestor_maximum),
        )
    }

    /// Applies block-length EDNS Padding for an encrypted DNS transport.
    ///
    /// The Padding option is removed before measuring, then reinserted as the
    /// final EDNS option. The smallest aligned length that includes the
    /// Padding option's four-octet header is selected. If that block exceeds
    /// the size ceiling but a zero-length option fits, the zero-length option
    /// is retained; if even its header does not fit, padding is omitted.
    /// Calculations always use the DNS message itself and never a TCP frame
    /// prefix, as required by RFC 8467 section 3. Queries are additionally
    /// capped at their own effective EDNS requestor payload size, as required
    /// by RFC 7830 section 4.
    ///
    /// This API is deliberately specific to encrypted transports because RFC
    /// 8467 does not recommend padding cleartext DNS.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid block size, missing or invalid EDNS,
    /// an already-oversized message, or an encoding failure. On error, the
    /// original message is unchanged.
    pub fn pad_to_block_size_for_encrypted_transport(
        &mut self,
        block_size: usize,
        maximum_message_octets: usize,
    ) -> Result<PaddingOutcome, PaddingPolicyError> {
        if block_size == 0 || block_size > MAX_DNS_MESSAGE_OCTETS {
            return Err(PaddingPolicyError::InvalidBlockSize { block_size });
        }

        let mut candidate = self.clone();
        let mut edns = candidate.edns()?.ok_or(PaddingPolicyError::MissingEdns)?;
        edns.validate_options()?;
        let maximum_message_octets =
            maximum_message_octets
                .min(MAX_DNS_MESSAGE_OCTETS)
                .min(if candidate.headers.qr {
                    MAX_DNS_MESSAGE_OCTETS
                } else {
                    usize::from(edns.effective_udp_payload_size())
                });
        let padding_only_transfer = candidate.headers.qr
            && candidate.headers.aa
            && !candidate.headers.tc
            && (candidate.questions.is_empty()
                || matches!(
                    candidate.questions.as_slice(),
                    [question] if matches!(question.qtype, crate::QueryType::AXFR | crate::QueryType::IXFR)
                ))
            && candidate.answers.is_empty()
            && candidate.authorities.is_empty()
            && matches!(candidate.additionals.as_slice(), [record]
                if record.rtype == RecordType::OPT)
            && edns.padding().is_some();
        edns.remove_padding();
        let opt_index = candidate
            .additionals
            .iter()
            .position(|record| record.rtype == RecordType::OPT)
            .expect("validated EDNS has an OPT record");
        candidate.additionals[opt_index] = edns.clone().into_record();

        let unpadded_candidate = candidate;
        let unpadded_octets = if padding_only_transfer {
            // The unpadded form is intentionally not wire-valid: RFC 9103
            // permits an empty transfer frame only when its OPT contains
            // Padding. Measure the valid zero-length form below and subtract
            // the four-octet option header for block-size calculations.
            let mut zero_padding_edns = edns.clone();
            zero_padding_edns.set_padding(0);
            let mut zero_padding_candidate = unpadded_candidate.clone();
            zero_padding_candidate.additionals[opt_index] = zero_padding_edns.into_record();
            zero_padding_candidate
                .into_wire()?
                .len()
                .checked_sub(4)
                .expect("zero-length Padding has a four-octet option header")
        } else {
            unpadded_candidate.clone().into_wire()?.len()
        };
        if unpadded_octets > maximum_message_octets {
            return Err(PaddingPolicyError::MessageTooLarge {
                message_octets: unpadded_octets,
                maximum_message_octets,
            });
        }

        edns.set_padding(0);
        let mut zero_padding_candidate = unpadded_candidate.clone();
        zero_padding_candidate.additionals[opt_index] = edns.clone().into_record();
        let zero_padding_octets = match zero_padding_candidate.into_wire() {
            Ok(wire) => wire.len(),
            Err(WireError::LengthOverflow { .. }) => {
                *self = unpadded_candidate;
                return Ok(PaddingOutcome::OmittedInsufficientSpace {
                    message_octets: unpadded_octets,
                });
            }
            Err(error) => return Err(error.into()),
        };
        if zero_padding_octets > maximum_message_octets {
            if padding_only_transfer {
                return Err(PaddingPolicyError::MessageTooLarge {
                    message_octets: zero_padding_octets,
                    maximum_message_octets,
                });
            }
            *self = unpadded_candidate;
            return Ok(PaddingOutcome::OmittedInsufficientSpace {
                message_octets: unpadded_octets,
            });
        }

        let aligned_octets = zero_padding_octets
            .checked_add(block_size - 1)
            .map(|length| length / block_size * block_size);
        let mut padding_octets = aligned_octets
            .filter(|&length| length <= maximum_message_octets)
            .map_or(0, |length| length - zero_padding_octets);

        let (candidate, padding_octets, message_octets) = loop {
            let Ok(encoded_padding_octets) = u16::try_from(padding_octets) else {
                break (zero_padding_candidate, 0, zero_padding_octets);
            };
            edns.set_padding(encoded_padding_octets);
            let mut padded_candidate = unpadded_candidate.clone();
            padded_candidate.additionals[opt_index] = edns.clone().into_record();
            let message_octets = match padded_candidate.into_wire() {
                Ok(wire) => wire.len(),
                Err(WireError::LengthOverflow { .. }) => {
                    break (zero_padding_candidate, 0, zero_padding_octets);
                }
                Err(error) => return Err(error.into()),
            };
            if message_octets > maximum_message_octets {
                break (zero_padding_candidate, 0, zero_padding_octets);
            }
            if message_octets % block_size == 0 {
                break (padded_candidate, encoded_padding_octets, message_octets);
            }

            let additional_padding = block_size - message_octets % block_size;
            let Some(next_padding_octets) = padding_octets.checked_add(additional_padding) else {
                break (zero_padding_candidate, 0, zero_padding_octets);
            };
            if next_padding_octets > usize::from(u16::MAX)
                || zero_padding_octets.saturating_add(next_padding_octets) > maximum_message_octets
            {
                break (zero_padding_candidate, 0, zero_padding_octets);
            }
            padding_octets = next_padding_octets;
        };
        let block_aligned = message_octets % block_size == 0;
        *self = candidate;

        Ok(PaddingOutcome::Padded {
            padding_octets,
            message_octets,
            block_aligned,
        })
    }
}

#[cfg(test)]
mod tests;

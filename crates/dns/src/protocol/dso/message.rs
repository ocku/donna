use super::*;

/// A complete DSO message with a primary TLV followed by optional TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsoMessage {
    /// DNS MESSAGE ID. Zero denotes a unidirectional message.
    pub id: u16,
    /// DNS QR bit.
    pub response: bool,
    /// Four-bit DNS RCODE.
    pub rcode: u8,
    /// Primary and additional TLVs in wire order.
    pub tlvs: Vec<DsoTlv>,
}

impl DsoMessage {
    /// Encodes the 12-byte zero-count DSO header and its TLVs.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid RCODE, missing TLVs, oversized TLVs, or
    /// invalid direction/ID rules for DNS Push operations.
    pub fn into_wire(&self) -> Result<Vec<u8>, DsoError> {
        self.validate()?;
        let mut encoder = Encoder::new();
        encoder.write_u16(self.id);
        encoder.write_u16(
            (u16::from(self.response) << 15)
                | (u16::from(DSO_OPCODE) << 11)
                | u16::from(self.rcode),
        );
        for _ in 0..4 {
            encoder.write_u16(0);
        }
        for tlv in &self.tlvs {
            let length = u16::try_from(tlv.data.len()).map_err(|_| DsoError::TlvTooLong {
                code: tlv.code,
                length: tlv.data.len(),
            })?;
            encoder.write_u16(tlv.code);
            encoder.write_u16(length);
            encoder.write_exact(&tlv.data);
        }
        let bytes = encoder.into_bytes();
        validate_message_length(bytes.len())?;
        Ok(bytes)
    }

    /// Decodes a complete DSO message.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed header/TLV data or invalid DNS Push
    /// direction and ID rules.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, DsoError> {
        validate_message_length(bytes.len())?;
        if bytes.len() < 12 {
            return Err(DsoError::Wire(WireError::Truncated {
                position: 0,
                needed: 12,
                remaining: bytes.len(),
            }));
        }
        let mut decoder = Decoder::new(bytes);
        let id = decoder.read_u16()?;
        let flags = decoder.read_u16()?;
        let response = flags & 0x8000 != 0;
        let opcode = ((flags >> 11) & 0x0f) as u8;
        let rcode = (flags & 0x0f) as u8;
        // RFC 8490 requires senders to clear Z, but receivers to ignore it.
        if opcode != DSO_OPCODE {
            return Err(DsoError::InvalidHeader);
        }
        for _ in 0..4 {
            if decoder.read_u16()? != 0 {
                return Err(DsoError::InvalidHeader);
            }
        }
        let mut tlvs = Vec::new();
        while decoder.remaining() != 0 {
            let code = decoder.read_u16()?;
            let length = usize::from(decoder.read_u16()?);
            let data = decoder.read_exact(length)?.to_vec();
            tlvs.push(DsoTlv { code, data });
        }
        if response {
            // RFC 8765 Section 6.2.2 requires receivers to process the
            // response while silently ignoring any SUBSCRIBE TLV.
            tlvs.retain(|tlv| tlv.code != DNS_PUSH_SUBSCRIBE);
        }
        let message = Self {
            id,
            response,
            rcode,
            tlvs,
        };
        message.validate()?;
        Ok(message)
    }

    fn validate(&self) -> Result<(), DsoError> {
        if self.rcode > 0x0f || (self.tlvs.is_empty() && !self.response) {
            return Err(DsoError::InvalidHeader);
        }
        if self
            .tlvs
            .first()
            .is_some_and(|tlv| tlv.code == DNS_PUSH_UPDATE)
        {
            let length = 12
                + self
                    .tlvs
                    .iter()
                    .map(|tlv| 4 + tlv.data.len())
                    .sum::<usize>();
            if length > 16_382 {
                return Err(DsoError::PushMessageTooLong(length));
            }
        }
        self.validate_base_tlv_contexts()?;
        if self.response {
            // RFC 8765 Section 6.6 forbids every Push TLV in either
            // primary or additional response context.
            if self.tlvs.iter().any(|tlv| {
                matches!(
                    tlv.code,
                    DNS_PUSH_SUBSCRIBE
                        | DNS_PUSH_UPDATE
                        | DNS_PUSH_UNSUBSCRIBE
                        | DNS_PUSH_RECONFIRM
                )
            }) {
                return Err(DsoError::InvalidHeader);
            }
            return (self.id != 0)
                .then_some(())
                .ok_or(DsoError::InvalidMessageId);
        }
        let primary = self.tlvs[0].code;
        match primary {
            DNS_PUSH_SUBSCRIBE if !self.response && self.id == 0 => {
                return Err(DsoError::InvalidMessageId);
            }
            DNS_PUSH_UPDATE | DNS_PUSH_UNSUBSCRIBE | DNS_PUSH_RECONFIRM
                if self.id != 0 || self.response =>
            {
                return Err(DsoError::InvalidMessageId);
            }
            _ => {}
        }
        if matches!(
            primary,
            DNS_PUSH_UPDATE | DNS_PUSH_UNSUBSCRIBE | DNS_PUSH_RECONFIRM
        ) && self.tlvs.len() != 1
        {
            return Err(DsoError::InvalidHeader);
        }
        if primary == DSO_RETRY_DELAY && self.id != 0 {
            return Err(DsoError::InvalidMessageId);
        }
        if self.tlvs[1..].iter().any(|tlv| {
            matches!(
                tlv.code,
                DNS_PUSH_SUBSCRIBE
                    | DNS_PUSH_UPDATE
                    | DNS_PUSH_UNSUBSCRIBE
                    | DNS_PUSH_RECONFIRM
                    | DSO_KEEPALIVE
            )
        }) {
            return Err(DsoError::InvalidHeader);
        }
        Ok(())
    }

    fn validate_base_tlv_contexts(&self) -> Result<(), DsoError> {
        for (index, tlv) in self.tlvs.iter().enumerate() {
            // Response Additional TLVs may occur without a Response Primary
            // TLV (RFC 8490 Section 5.4.2), including Retry Delay and Padding.
            let valid = match tlv.code {
                DSO_KEEPALIVE => index == 0,
                DSO_RETRY_DELAY => {
                    if self.response {
                        self.rcode != 0
                    } else {
                        index == 0 && self.id == 0
                    }
                }
                3 => self.response || index != 0,
                _ => true,
            };
            if !valid {
                return Err(DsoError::InvalidHeader);
            }
        }
        Ok(())
    }

    /// Returns the primary TLV, if present.
    ///
    /// Successful DSO responses are permitted to contain no TLVs.
    pub fn primary(&self) -> Option<&DsoTlv> {
        self.tlvs.first()
    }
}

fn validate_message_length(length: usize) -> Result<(), DsoError> {
    if length > usize::from(u16::MAX) {
        return Err(DsoError::Wire(WireError::LengthOverflow {
            field: "message",
            length,
            maximum: usize::from(u16::MAX),
        }));
    }
    Ok(())
}

use super::*;

/// One DNS Stateful Operations TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsoTlv {
    /// DSO-TYPE value.
    pub code: u16,
    /// DSO-DATA octets.
    pub data: Vec<u8>,
}

impl DsoTlv {
    /// Constructs a Keepalive TLV.
    pub fn keepalive(inactivity_timeout: Duration, keepalive_interval: Duration) -> Self {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&duration_millis(inactivity_timeout).to_be_bytes());
        data.extend_from_slice(&duration_millis(keepalive_interval).to_be_bytes());
        Self {
            code: DSO_KEEPALIVE,
            data,
        }
    }

    /// Parses a Keepalive TLV into inactivity and keepalive durations.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is an eight-octet Keepalive TLV.
    pub fn keepalive_values(&self) -> Result<(Duration, Duration), DsoError> {
        if self.code != DSO_KEEPALIVE || self.data.len() != 8 {
            return Err(DsoError::MalformedTlv(self.code));
        }
        Ok((
            Duration::from_millis(u64::from(u32::from_be_bytes(
                self.data[0..4].try_into().expect("checked length"),
            ))),
            Duration::from_millis(u64::from(u32::from_be_bytes(
                self.data[4..8].try_into().expect("checked length"),
            ))),
        ))
    }

    /// Constructs a Retry Delay TLV.
    pub fn retry_delay(delay: Duration) -> Self {
        Self {
            code: DSO_RETRY_DELAY,
            data: duration_millis(delay).to_be_bytes().to_vec(),
        }
    }

    /// Parses a Retry Delay TLV.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is a four-octet Retry Delay TLV.
    pub fn retry_delay_value(&self) -> Result<Duration, DsoError> {
        if self.code != DSO_RETRY_DELAY || self.data.len() != 4 {
            return Err(DsoError::MalformedTlv(self.code));
        }
        Ok(Duration::from_millis(u64::from(u32::from_be_bytes(
            self.data[..4].try_into().expect("checked length"),
        ))))
    }
}

fn duration_millis(duration: Duration) -> u32 {
    duration.as_millis().min(u128::from(u32::MAX)) as u32
}

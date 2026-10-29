use super::*;

/// Endpoint role used for RFC 8490 timeout behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsoEndpoint {
    /// Initiating client, which sends keepalives and closes inactive sessions.
    Client,
    /// Accepting server, which aborts delinquent clients.
    Server,
}

/// Action due from a DSO session at a particular instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsoSessionAction {
    /// No timer requires action.
    None,
    /// Client must send a Keepalive request.
    SendKeepalive,
    /// Client must gracefully close an inactive session.
    GracefulClose,
    /// Server should forcibly abort a delinquent session.
    Abort,
}

/// RFC 8490 inactivity and keepalive timer state.
pub struct DsoSession {
    endpoint: DsoEndpoint,
    inactivity_timeout: Option<Duration>,
    keepalive_interval: Option<Duration>,
    last_non_keepalive: Instant,
    last_message: Instant,
    active_operations: usize,
}

impl DsoSession {
    /// Creates a session with RFC 8490's default 15-second timers.
    #[must_use]
    pub fn new(endpoint: DsoEndpoint, now: Instant) -> Self {
        Self {
            endpoint,
            inactivity_timeout: Some(Duration::from_secs(15)),
            keepalive_interval: Some(Duration::from_secs(15)),
            last_non_keepalive: now,
            last_message: now,
            active_operations: 0,
        }
    }

    /// Applies timeout values received by a client from its server.
    ///
    /// A value of `0xFFFFFFFF` milliseconds represents infinity. Keepalive
    /// intervals below ten seconds are a fatal protocol error.
    ///
    /// # Errors
    ///
    /// Returns an error on a server endpoint, malformed TLV, or an interval
    /// below RFC 8490's ten-second minimum.
    pub fn apply_server_keepalive(
        &mut self,
        keepalive: &DsoTlv,
        now: Instant,
    ) -> Result<(), DsoError> {
        if self.endpoint != DsoEndpoint::Client {
            return Err(DsoError::WrongDirection);
        }
        self.apply_keepalive_values(keepalive, now)
    }

    /// Applies the timeout values granted by this server in an outgoing
    /// Keepalive response or server-initiated Keepalive message.
    ///
    /// Call when sending the message, with the values actually sent to the
    /// client, rather than the client's requested values. This updates the
    /// delinquency deadlines and records Keepalive traffic without resetting
    /// the inactivity timer. `0xFFFFFFFF` milliseconds disables that timer.
    ///
    /// # Errors
    ///
    /// Returns an error on a client endpoint, malformed TLV, or a keepalive
    /// interval below RFC 8490's ten-second minimum. Errors leave state unchanged.
    pub fn configure_server_keepalive(
        &mut self,
        keepalive: &DsoTlv,
        now: Instant,
    ) -> Result<(), DsoError> {
        if self.endpoint != DsoEndpoint::Server {
            return Err(DsoError::WrongDirection);
        }
        self.apply_keepalive_values(keepalive, now)
    }

    fn apply_keepalive_values(&mut self, keepalive: &DsoTlv, now: Instant) -> Result<(), DsoError> {
        let (inactivity, interval) = raw_keepalive_values(keepalive)?;
        if interval != u32::MAX && interval < 10_000 {
            return Err(DsoError::InvalidKeepaliveInterval(interval));
        }
        self.inactivity_timeout = finite_millis(inactivity);
        self.keepalive_interval = finite_millis(interval);
        self.record_message(now, true);
        Ok(())
    }

    /// Sets the number of outstanding short- or long-lived operations.
    ///
    /// While nonzero, the inactivity timer is cleared; the keepalive timer
    /// continues to run. When the last operation ends, inactivity starts
    /// at the time of this call. This method samples [`Instant::now`]; if
    /// the session uses caller-supplied or simulated instants, use
    /// [`Self::set_active_operations_at`] with the same timeline instead.
    pub fn set_active_operations(&mut self, count: usize) {
        self.set_active_operations_at(count, Instant::now());
    }

    /// Sets the number of active operations at a caller-supplied instant.
    ///
    /// Use the same clock as the instants passed to the other session methods.
    pub fn set_active_operations_at(&mut self, count: usize, now: Instant) {
        if self.active_operations > 0 && count == 0 {
            self.last_non_keepalive = now;
        }
        self.active_operations = count;
    }

    /// Records sent or received DNS traffic.
    ///
    /// Keepalive messages reset only the keepalive timer. Other complete DNS
    /// messages reset both timers.
    pub fn record_message(&mut self, now: Instant, is_keepalive: bool) {
        self.last_message = now;
        if !is_keepalive {
            self.last_non_keepalive = now;
        }
    }

    /// Returns the timer action due at `now`.
    #[must_use]
    pub fn action(&self, now: Instant) -> DsoSessionAction {
        let message_idle = now.saturating_duration_since(self.last_message);
        let activity_idle = now.saturating_duration_since(self.last_non_keepalive);
        match self.endpoint {
            DsoEndpoint::Client => {
                if self.active_operations == 0
                    && self
                        .inactivity_timeout
                        .is_some_and(|timeout| activity_idle >= timeout)
                {
                    return DsoSessionAction::GracefulClose;
                }
                if self
                    .keepalive_interval
                    .is_some_and(|interval| message_idle >= interval)
                {
                    return DsoSessionAction::SendKeepalive;
                }
                DsoSessionAction::None
            }
            DsoEndpoint::Server => {
                let inactive_delinquent = self.active_operations == 0
                    && self.inactivity_timeout.is_some_and(|timeout| {
                        activity_idle >= timeout.saturating_mul(2).max(Duration::from_secs(5))
                    });
                let keepalive_delinquent = self
                    .keepalive_interval
                    .is_some_and(|interval| message_idle >= interval.saturating_mul(2));
                if inactive_delinquent || keepalive_delinquent {
                    DsoSessionAction::Abort
                } else {
                    DsoSessionAction::None
                }
            }
        }
    }
}

fn raw_keepalive_values(tlv: &DsoTlv) -> Result<(u32, u32), DsoError> {
    if tlv.code != DSO_KEEPALIVE || tlv.data.len() != 8 {
        return Err(DsoError::MalformedTlv(tlv.code));
    }
    Ok((
        u32::from_be_bytes(tlv.data[0..4].try_into().expect("checked length")),
        u32::from_be_bytes(tlv.data[4..8].try_into().expect("checked length")),
    ))
}

fn finite_millis(value: u32) -> Option<Duration> {
    (value != u32::MAX).then(|| Duration::from_millis(u64::from(value)))
}

#[cfg(test)]
mod tests;

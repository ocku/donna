use super::*;

/// Externally visible phase of an LLQ client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlqClientStatus {
    /// Setup request is pending or being retransmitted.
    SettingUp,
    /// Setup challenge was accepted and its final acknowledgment is pending.
    AwaitingSetupAck,
    /// Lease is active.
    Active,
    /// A SERV-FULL retry delay is in effect.
    RetryDelayed,
    /// Server declared the data static; polling is forbidden.
    Static,
    /// Setup or refresh failed.
    Failed,
    /// Active lease expired without successful refresh.
    Expired,
}

#[derive(Debug, Clone, Copy)]
enum ClientState {
    SettingUp {
        attempts: u8,
        last_sent: Instant,
    },
    AwaitingSetupAck {
        id: u64,
        lease: u32,
        attempts: u8,
        last_sent: Instant,
    },
    Active {
        id: u64,
        lease: u32,
        started: Instant,
        refresh_attempts: u8,
    },
    RetryDelayed {
        retry_at: Instant,
    },
    Static,
    Failed,
}

/// Deterministic RFC 8764 client handshake, event, and lease state.
pub struct LlqClient {
    question: Question,
    requested_lease: u32,
    state: ClientState,
}

impl LlqClient {
    /// Creates an LLQ and records its first setup transmission at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical question, QTYPE ANY, QCLASS
    /// ANY/NONE or reserved zero, or a zero lease.
    pub fn start(
        question: Question,
        requested_lease: u32,
        now: Instant,
    ) -> Result<(Self, LlqOption), LlqError> {
        validate_question(&question)?;
        if requested_lease == 0 {
            return Err(LlqError::InvalidLease);
        }
        let request = setup_request(requested_lease);
        Ok((
            Self {
                question,
                requested_lease,
                state: ClientState::SettingUp {
                    attempts: 1,
                    last_sent: now,
                },
            },
            request,
        ))
    }

    /// Returns the subscribed question.
    #[must_use]
    pub const fn question(&self) -> &Question {
        &self.question
    }

    /// Returns the current externally visible client state.
    #[must_use]
    pub fn status(&self, now: Instant) -> LlqClientStatus {
        match self.state {
            ClientState::SettingUp { .. } => LlqClientStatus::SettingUp,
            ClientState::AwaitingSetupAck { .. } => LlqClientStatus::AwaitingSetupAck,
            ClientState::Active { lease, started, .. }
                if now.saturating_duration_since(started)
                    >= Duration::from_secs(u64::from(lease)) =>
            {
                LlqClientStatus::Expired
            }
            ClientState::Active { .. } => LlqClientStatus::Active,
            ClientState::RetryDelayed { .. } => LlqClientStatus::RetryDelayed,
            ClientState::Static => LlqClientStatus::Static,
            ClientState::Failed => LlqClientStatus::Failed,
        }
    }

    /// Retransmits setup requests or responses after 2 and 4 seconds, then
    /// fails 8 seconds after the
    /// third transmission.
    ///
    /// `Ok(None)` means no transmission is due yet or setup has just failed.
    ///
    /// # Errors
    ///
    /// Returns an error unless setup is currently pending.
    pub fn retry_setup(&mut self, now: Instant) -> Result<Option<LlqOption>, LlqError> {
        let (attempts, last_sent, response) = match &mut self.state {
            ClientState::SettingUp {
                attempts,
                last_sent,
            } => (attempts, last_sent, setup_request(self.requested_lease)),
            ClientState::AwaitingSetupAck {
                id,
                lease,
                attempts,
                last_sent,
            } => {
                let mut response = setup_request(*lease);
                response.id = *id;
                (attempts, last_sent, response)
            }
            _ => return Err(LlqError::InvalidState),
        };
        let wait = match *attempts {
            1 => Duration::from_secs(2),
            2 => Duration::from_secs(4),
            3 => Duration::from_secs(8),
            _ => return Err(LlqError::InvalidState),
        };
        if now.saturating_duration_since(*last_sent) < wait {
            return Ok(None);
        }
        if *attempts == 3 {
            self.state = ClientState::Failed;
            return Ok(None);
        }
        *attempts += 1;
        *last_sent = now;
        Ok(Some(response))
    }

    /// Accepts a setup challenge and returns the option to echo in the
    /// challenge response.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed semantics or the wrong client state.
    pub fn accept_challenge(
        &mut self,
        challenge: LlqOption,
        now: Instant,
    ) -> Result<Option<LlqOption>, LlqError> {
        if !matches!(self.state, ClientState::SettingUp { .. })
            || challenge.version != LLQ_VERSION
            || challenge.opcode != LlqOpcode::Setup
        {
            return Err(LlqError::InvalidState);
        }
        match challenge.response_code {
            LlqResponseCode::NoError if challenge.id != 0 && challenge.lease != 0 => {
                self.state = ClientState::AwaitingSetupAck {
                    id: challenge.id,
                    lease: challenge.lease,
                    attempts: 1,
                    last_sent: now,
                };
                Ok(Some(challenge))
            }
            LlqResponseCode::ServerFull if challenge.id == 0 => {
                self.state = ClientState::RetryDelayed {
                    retry_at: now
                        .checked_add(Duration::from_secs(u64::from(challenge.lease)))
                        .unwrap_or(now),
                };
                Ok(None)
            }
            LlqResponseCode::Static if challenge.id == 0 && challenge.lease == 0 => {
                self.state = ClientState::Static;
                Ok(None)
            }
            LlqResponseCode::NoError | LlqResponseCode::ServerFull | LlqResponseCode::Static => {
                Err(LlqError::MalformedOption)
            }
            _ if challenge.id == 0 && challenge.lease == 0 => {
                self.state = ClientState::Failed;
                Ok(None)
            }
            _ => Err(LlqError::MalformedOption),
        }
    }

    /// Accepts the fourth setup message and starts the granted lease.
    ///
    /// # Errors
    ///
    /// Returns an error unless the echoed ID and lease match the challenge.
    pub fn accept_setup_ack(&mut self, ack: LlqOption, now: Instant) -> Result<(), LlqError> {
        let ClientState::AwaitingSetupAck { id, lease, .. } = self.state else {
            return Err(LlqError::InvalidState);
        };
        if ack.version != LLQ_VERSION
            || ack.opcode != LlqOpcode::Setup
            || ack.response_code != LlqResponseCode::NoError
            || ack.id != id
            || ack.lease == 0
            || ack.lease > lease
        {
            return Err(LlqError::MalformedOption);
        }
        self.state = active(ack.id, ack.lease, now);
        Ok(())
    }

    /// Produces refresh attempts at 80%, 90%, and 95% of the lease.
    ///
    /// # Errors
    ///
    /// Returns an error unless an unexpired lease is active.
    pub fn refresh(&mut self, now: Instant) -> Result<Option<LlqOption>, LlqError> {
        let ClientState::Active {
            id,
            lease,
            started,
            refresh_attempts,
        } = &mut self.state
        else {
            return Err(LlqError::InvalidState);
        };
        let elapsed = now.saturating_duration_since(*started).as_secs_f64();
        if elapsed >= f64::from(*lease) {
            return Err(LlqError::LeaseExpired);
        }
        let threshold = match *refresh_attempts {
            0 => 0.80,
            1 => 0.90,
            2 => 0.95,
            _ => return Ok(None),
        };
        if elapsed < f64::from(*lease) * threshold {
            return Ok(None);
        }
        *refresh_attempts += 1;
        Ok(Some(LlqOption {
            version: LLQ_VERSION,
            opcode: LlqOpcode::Refresh,
            response_code: LlqResponseCode::NoError,
            id: *id,
            lease: *lease,
        }))
    }

    /// Accepts a refresh acknowledgment and restarts the granted lease.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched ID, server error, or inactive lease.
    pub fn accept_refresh_ack(&mut self, ack: LlqOption, now: Instant) -> Result<(), LlqError> {
        let ClientState::Active { id, .. } = self.state else {
            return Err(LlqError::InvalidState);
        };
        if ack.version != LLQ_VERSION
            || ack.opcode != LlqOpcode::Refresh
            || ack.response_code != LlqResponseCode::NoError
            || ack.id != id
            || ack.lease == 0
        {
            self.state = ClientState::Failed;
            return Err(LlqError::MalformedOption);
        }
        self.state = active(id, ack.lease, now);
        Ok(())
    }

    /// Builds a zero-lease refresh to terminate the active LLQ.
    ///
    /// # Errors
    ///
    /// Returns an error unless a lease is active.
    pub fn terminate(&mut self) -> Result<LlqOption, LlqError> {
        let ClientState::Active { id, .. } = self.state else {
            return Err(LlqError::InvalidState);
        };
        self.state = ClientState::Failed;
        Ok(LlqOption {
            version: LLQ_VERSION,
            opcode: LlqOpcode::Refresh,
            response_code: LlqResponseCode::NoError,
            id,
            lease: 0,
        })
    }

    /// Validates an event and returns the option and DNS message ID the client
    /// must echo in its acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns an error for an expired/inactive lease or mismatched event.
    pub fn acknowledge_event(
        &self,
        message_id: u16,
        event: LlqOption,
        now: Instant,
    ) -> Result<LlqEventAck, LlqError> {
        let ClientState::Active {
            id, lease, started, ..
        } = self.state
        else {
            return Err(LlqError::InvalidState);
        };
        if now.saturating_duration_since(started) >= Duration::from_secs(u64::from(lease)) {
            return Err(LlqError::LeaseExpired);
        }
        if event.version != LLQ_VERSION
            || event.opcode != LlqOpcode::Event
            || event.response_code != LlqResponseCode::NoError
            || event.id != id
            || event.lease != 0
        {
            return Err(LlqError::MalformedOption);
        }
        Ok(LlqEventAck {
            message_id,
            option: event,
        })
    }

    /// Restarts setup after a SERV-FULL delay has elapsed.
    ///
    /// # Errors
    ///
    /// Returns an error unless the retry delay has elapsed.
    pub fn retry_after_delay(&mut self, now: Instant) -> Result<LlqOption, LlqError> {
        let ClientState::RetryDelayed { retry_at } = self.state else {
            return Err(LlqError::InvalidState);
        };
        if now < retry_at {
            return Err(LlqError::RetryTooEarly);
        }
        self.state = ClientState::SettingUp {
            attempts: 1,
            last_sent: now,
        };
        Ok(setup_request(self.requested_lease))
    }
}

fn active(id: u64, lease: u32, now: Instant) -> ClientState {
    ClientState::Active {
        id,
        lease,
        started: now,
        refresh_attempts: 0,
    }
}

fn setup_request(lease: u32) -> LlqOption {
    LlqOption {
        version: LLQ_VERSION,
        opcode: LlqOpcode::Setup,
        response_code: LlqResponseCode::NoError,
        id: 0,
        lease,
    }
}

fn validate_question(question: &Question) -> Result<(), LlqError> {
    if !question.is_wire_canonical()
        || question.qtype == QueryType::ANY
        || matches!(question.qclass.value(), 0 | 254 | 255)
    {
        return Err(LlqError::InvalidQuestion);
    }
    Ok(())
}

use super::*;

/// Observable action produced by an mDNS unique-name registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsRegistrationAction {
    /// Send the next probe query.
    Probe,
    /// Send an unsolicited announcement response.
    Announce,
    /// Immediately defend an established name with an authoritative answer.
    Defend,
    /// Relinquish and choose a new name.
    Relinquish,
    /// Wait one second, then retry after losing a simultaneous probe.
    Backoff,
}

/// Current unique-name registration phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsRegistrationState {
    /// Waiting for or transmitting the three probes.
    Probing,
    /// Transmitting the two initial announcements.
    Announcing,
    /// Third probe was sent; waiting 250 ms before announcing.
    WaitingToAnnounce,
    /// A simultaneous-probe loss is in its one-second retry delay.
    BackingOff,
    /// Name is established.
    Established,
    /// A conflict requires the caller to choose another name.
    Conflicted,
}

/// Deterministic RFC 6762 probing, announcement, and conflict resolution.
///
/// The caller must track conflicts across names/registrations and enforce the
/// five-second retry minimum after fifteen conflicts in ten seconds (§8.1).
pub struct MdnsRegistration {
    state: MdnsRegistrationState,
    next_at: Instant,
    probes_sent: u8,
    announcements_sent: u8,
}

impl MdnsRegistration {
    /// Starts probing after an initial randomized delay, capped at 250 ms.
    pub fn new(now: Instant, initial_delay: Duration) -> Self {
        let delay = initial_delay.min(Duration::from_millis(250));
        Self {
            state: MdnsRegistrationState::Probing,
            next_at: now.checked_add(delay).unwrap_or(now),
            probes_sent: 0,
            announcements_sent: 0,
        }
    }

    /// Returns the current registration phase.
    pub const fn state(&self) -> MdnsRegistrationState {
        self.state
    }

    /// Produces a due probe or announcement and advances its timer.
    pub fn poll(&mut self, now: Instant) -> Option<MdnsRegistrationAction> {
        if now < self.next_at {
            return None;
        }
        match self.state {
            MdnsRegistrationState::Probing => {
                self.probes_sent += 1;
                if self.probes_sent == 3 {
                    self.state = MdnsRegistrationState::WaitingToAnnounce;
                    self.next_at = now.checked_add(Duration::from_millis(250)).unwrap_or(now);
                } else {
                    self.next_at = now.checked_add(Duration::from_millis(250)).unwrap_or(now);
                }
                Some(MdnsRegistrationAction::Probe)
            }
            MdnsRegistrationState::WaitingToAnnounce => {
                self.state = MdnsRegistrationState::Announcing;
                self.announcements_sent = 1;
                self.next_at = now.checked_add(Duration::from_secs(1)).unwrap_or(now);
                Some(MdnsRegistrationAction::Announce)
            }
            MdnsRegistrationState::Announcing => {
                self.announcements_sent += 1;
                self.state = MdnsRegistrationState::Established;
                Some(MdnsRegistrationAction::Announce)
            }
            MdnsRegistrationState::BackingOff => {
                self.state = MdnsRegistrationState::Probing;
                self.probes_sent = 1;
                self.next_at = now.checked_add(Duration::from_millis(250)).unwrap_or(now);
                Some(MdnsRegistrationAction::Probe)
            }
            MdnsRegistrationState::Established | MdnsRegistrationState::Conflicted => None,
        }
    }

    /// Applies a simultaneous probe query's tie-break result.
    /// Established names answer probes regardless of the lexical ordering.
    pub fn probe(
        &mut self,
        outcome: ProbeTieBreak,
        now: Instant,
    ) -> Option<MdnsRegistrationAction> {
        if outcome == ProbeTieBreak::Equal {
            return None;
        }
        match self.state {
            MdnsRegistrationState::Probing | MdnsRegistrationState::WaitingToAnnounce
                if outcome == ProbeTieBreak::Lose =>
            {
                self.state = MdnsRegistrationState::BackingOff;
                self.next_at = now.checked_add(Duration::from_secs(1)).unwrap_or(now);
                Some(MdnsRegistrationAction::Backoff)
            }
            MdnsRegistrationState::Announcing | MdnsRegistrationState::Established => {
                Some(MdnsRegistrationAction::Defend)
            }
            _ => None,
        }
    }

    /// Applies a response containing a conflicting record (§8.1 and §9).
    ///
    /// Call only after checking the record's name, class, type and inconsistent
    /// RDATA: identical RDATA is never a conflict. During ANY probing, §8.1
    /// instead treats any answer with the probed name as conflicting.
    /// Lexical tie-breaking applies only to probe queries, never responses.
    pub fn response_conflict(&mut self, now: Instant) -> Option<MdnsRegistrationAction> {
        match self.state {
            MdnsRegistrationState::Probing if self.probes_sent == 0 => None,
            MdnsRegistrationState::Probing | MdnsRegistrationState::WaitingToAnnounce => {
                self.state = MdnsRegistrationState::Conflicted;
                Some(MdnsRegistrationAction::Relinquish)
            }
            MdnsRegistrationState::Announcing | MdnsRegistrationState::Established => {
                self.state = MdnsRegistrationState::Probing;
                self.probes_sent = 0;
                self.announcements_sent = 0;
                self.next_at = now;
                self.poll(now)
            }
            MdnsRegistrationState::BackingOff | MdnsRegistrationState::Conflicted => None,
        }
    }

    /// Applies a simultaneous probe query. Use `response_conflict` for responses.
    pub fn conflict(
        &mut self,
        outcome: ProbeTieBreak,
        now: Instant,
    ) -> Option<MdnsRegistrationAction> {
        self.probe(outcome, now)
    }
}

#[cfg(test)]
mod tests;

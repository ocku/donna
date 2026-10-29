use super::*;

/// Stateful subscription registry with direction, uniqueness, authorization,
/// retry, and capacity enforcement.
pub struct DnsPushSubscriptions {
    capacity: usize,
    active: HashMap<u16, Question>,
    retry_at: Option<Instant>,
}

impl DnsPushSubscriptions {
    /// Creates a bounded subscription registry.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            active: HashMap::with_capacity(capacity),
            retry_at: None,
        }
    }

    /// Accepts one SUBSCRIBE request after applying caller authorization.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong direction, duplicate ID/question, refusal,
    /// or capacity exhaustion.
    pub fn subscribe(
        &mut self,
        message: &DsoMessage,
        authorize: impl FnOnce(&Question) -> bool,
    ) -> Result<&Question, DsoError> {
        if message.response
            || message.id == 0
            || message
                .primary()
                .is_none_or(|tlv| tlv.code != DNS_PUSH_SUBSCRIBE)
        {
            return Err(DsoError::WrongDirection);
        }
        let question = parse_push_subscribe(message.primary().expect("checked above"))?;
        if self.active.contains_key(&message.id)
            || self
                .active
                .values()
                .any(|active| same_question(active, &question))
        {
            return Err(DsoError::DuplicateSubscription);
        }
        if self.active.len() >= self.capacity {
            return Err(DsoError::SubscriptionLimit);
        }
        if !authorize(&question) {
            return Err(DsoError::NotAuthorized);
        }
        self.active.insert(message.id, question);
        Ok(&self.active[&message.id])
    }

    /// Applies an UNSUBSCRIBE message. Unknown IDs are ignored as required.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong message direction or malformed TLV.
    pub fn unsubscribe(&mut self, message: &DsoMessage) -> Result<(), DsoError> {
        if message.response
            || message.id != 0
            || message
                .primary()
                .is_none_or(|tlv| tlv.code != DNS_PUSH_UNSUBSCRIBE)
        {
            return Err(DsoError::WrongDirection);
        }
        self.active.remove(&parse_push_unsubscribe(
            message.primary().expect("checked above"),
        )?);
        Ok(())
    }

    /// Records a server Retry Delay and clears session-bound subscriptions.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed Retry Delay TLV.
    pub fn disconnect_with_retry(&mut self, retry: &DsoTlv, now: Instant) -> Result<(), DsoError> {
        let delay = retry.retry_delay_value()?;
        self.retry_at = Some(now.checked_add(delay).unwrap_or(now));
        self.active.clear();
        Ok(())
    }

    /// Returns whether reconnect is permitted by the last Retry Delay.
    pub fn can_reconnect(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|retry_at| now >= retry_at)
    }

    /// Returns the number of active subscriptions.
    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// Returns whether no subscriptions are active.
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}

pub(super) fn same_question(left: &Question, right: &Question) -> bool {
    left.qname.eq_dns(&right.qname) && left.qtype == right.qtype && left.qclass == right.qclass
}

use super::*;
impl<T: Transport> Resolver<T> {
    /// Returns the common direct positive-cache hit before resolution state is
    /// allocated.
    #[cfg(test)]
    pub(in crate::resolver) fn cached_positive_response(
        &self,
        question: &Question,
    ) -> Option<Message> {
        // Every cache read takes the policy lock so it cannot observe the gap
        // between inserting a negative entry and removing conflicting positive
        // entries (or the inverse operation).
        let _policy = self
            .cache_policy
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.positive_cache.get_question(question)
    }

    #[cfg(test)]
    pub(in crate::resolver) fn cached_negative_response(
        &self,
        question: &Question,
    ) -> Option<Message> {
        let _policy = self
            .cache_policy
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut reply = self.negative_cache.get(question)?;
        self.append_implicit_referral(&mut reply, question);
        Some(reply)
    }

    #[cfg(test)]
    pub(in crate::resolver) fn cache_positive_entries(
        &self,
        id: u16,
        reply: &Message,
        question: &Question,
    ) {
        self.cache_positive_entries_at(id, reply, question, std::time::Instant::now(), None);
    }
}

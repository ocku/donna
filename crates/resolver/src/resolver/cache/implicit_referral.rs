use super::*;
impl<T: Transport> Resolver<T> {
    /// Adds RFC 2308 section 6's implicit referral to a cached negative.
    ///
    /// Authoritative servers intentionally emit Type 2 negative responses
    /// without NS records for compatibility. An iterative resolver has
    /// normally learned the applicable delegation on the way to that server,
    /// so reuse the still-fresh delegation cache instead of weakening the
    /// authoritative server's response shape or extending any TTL.
    pub(super) fn append_implicit_referral(&self, reply: &mut Message, question: &Question) {
        if reply.headers.ad
            || reply
                .authorities
                .iter()
                .any(|record| record.rtype == RecordType::NS)
        {
            return;
        }
        self.delegation_cache
            .append_referral_records(question, &mut reply.authorities);
    }
}

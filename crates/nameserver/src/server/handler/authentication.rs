//! Authenticate requests and advance replay state before query/update policy.
use super::*;

type AuthenticationResult =
    Result<(dns::Message, Option<AuthenticatedRequest>), Option<dns::Message>>;

impl NameServer {
    pub(super) async fn authenticate_request(
        &self,
        request: &transport::DnsRequest,
    ) -> AuthenticationResult {
        let sig0_authentication = sig0::authenticate(
            request.message().clone(),
            request.wire_message(),
            &self.config.sig0_keys,
            sig0::unix_time_now(),
        );
        match sig0_authentication {
            sig0::Sig0Authentication::Rejected(response) => Err(Some(response)),
            sig0::Sig0Authentication::Authenticated {
                query,
                key,
                request_wire,
                signature,
                inception,
                expiration,
            } => {
                let now = sig0::unix_time_now() as u32;
                if !super::super::sig0_time_is_acceptable(
                    inception,
                    expiration,
                    now,
                    self.config.sig0_validity_window,
                ) {
                    return Err(Some(error_response(&query, RCode::NotAuthoritative)));
                }
                let principal = dns_name_key(key.verification_key().name());
                let mut replays = self.sig0_replays.lock().await;
                if !remember_sig0_request(&mut replays, principal, signature, expiration, now) {
                    drop(replays);
                    return Err(Some(error_response(&query, RCode::NotAuthoritative)));
                }
                drop(replays);
                Ok((
                    query,
                    Some(AuthenticatedRequest::Sig0 { key, request_wire }),
                ))
            }
            sig0::Sig0Authentication::Unsigned(query) => {
                self.authenticate_tsig(query, request.wire_message()).await
            }
        }
    }

    async fn authenticate_tsig(&self, query: dns::Message, wire: &[u8]) -> AuthenticationResult {
        let authentication = authenticate(query, wire, &self.config.tsig_keys, unix_time_now());
        match authentication {
            RequestAuthentication::Unsigned(query) => Ok((query, None)),
            RequestAuthentication::Rejected(response) => Err(Some(response)),
            RequestAuthentication::Authenticated {
                query,
                key,
                request_mac,
                original_id,
                fudge,
                time_signed,
            } => {
                let now = unix_time_now();
                let mut times = self.tsig_times.lock().await;
                let previous = times.get(&dns_name_key(key.name())).copied();
                if previous.is_some_and(|previous| time_signed < previous) {
                    drop(times);
                    return Err(signed_badtime_response(
                        &query,
                        &key,
                        &request_mac,
                        original_id,
                        time_signed,
                        fudge,
                        now,
                    )
                    .ok());
                }
                times
                    .entry(dns_name_key(key.name()))
                    .and_modify(|previous| *previous = (*previous).max(time_signed))
                    .or_insert(time_signed);
                drop(times);
                Ok((
                    query,
                    Some(AuthenticatedRequest::Tsig {
                        key,
                        request_mac,
                        original_id,
                        fudge,
                    }),
                ))
            }
        }
    }
}

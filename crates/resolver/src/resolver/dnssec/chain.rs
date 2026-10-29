use std::sync::Arc;

mod path;
mod validation;

use dns::{
    AuthenticatedDnskeySet, ClassType, DnssecValidation, DnssecValidationError, DomainName,
    Message, QClassType, QueryType, Question, RData, RecordType, authenticate_dnskey_with_anchor,
    authenticate_dnskey_with_ds,
};
use transport::Transport;

use crate::ResolveError;

use super::{
    super::{AlgorithmSignals, Resolver},
    records::{
        closest_soa_owner, parent_signer, records_at_type, signatures_covering, validation_result,
    },
};

use super::{
    key_cache::{AuthenticatedLifetime, CachedZone, ValidationTime, ZoneKey},
    zone_context::check_signature_time,
};

struct DelegationLink {
    child: DomainName,
    response: Message,
    has_ds: bool,
}

struct ChainValidation {
    keys: Arc<AuthenticatedDnskeySet>,
    ttl: u32,
    deadline: std::time::Instant,
    signature_ttl: u32,
    time: ValidationTime,
    class: ClassType,
    anchor: DomainName,
}

pub(super) enum ChainStatus {
    Secure {
        keys: Arc<AuthenticatedDnskeySet>,
        deadline: std::time::Instant,
        cached: bool,
        valid_until: u32,
    },
    Insecure {
        deadline: std::time::Instant,
        valid_until: u32,
    },
}

pub(super) struct RefreshedZone {
    keys: Arc<AuthenticatedDnskeySet>,
    deadline: std::time::Instant,
    at: ValidationTime,
    signature_ttl: u32,
}

impl RefreshedZone {
    pub(super) fn matches(&self, zone: &DomainName, class: ClassType) -> bool {
        self.keys.zone().eq_dns(zone) && self.keys.class() == class
    }

    pub(super) fn status(&self) -> Result<ChainStatus, ResolveError> {
        check_signature_time(self.at, self.signature_ttl)?;
        Ok(ChainStatus::Secure {
            keys: Arc::clone(&self.keys),
            deadline: self.deadline,
            cached: false,
            valid_until: self.at.unix.wrapping_add(self.signature_ttl),
        })
    }
}

impl<T: Transport> Resolver<T> {
    #[cfg(test)]
    pub(super) async fn authenticate_zone(
        &self,
        zone: &DomainName,
        class: ClassType,
        now: u32,
    ) -> Result<ChainStatus, ResolveError> {
        self.authenticate_zone_at(
            zone,
            class,
            ValidationTime {
                instant: std::time::Instant::now(),
                unix: now,
            },
        )
        .await
    }

    pub(super) async fn authenticate_zone_at(
        &self,
        zone: &DomainName,
        class: ClassType,
        time: ValidationTime,
    ) -> Result<ChainStatus, ResolveError> {
        let key = self.zone_cache_key(zone, class)?;
        let lookup_time = ValidationTime::now();
        if let Some(cached) = self
            .cached_authenticated_zone_backend(&key, lookup_time)
            .await?
        {
            return Ok(ChainStatus::Secure {
                keys: cached.keys,
                deadline: cached.deadline,
                cached: true,
                valid_until: cached.valid_until,
            });
        }
        let _gate = match self.authenticated_zones.gate(&key) {
            Some(gate) => Some(gate.lock_owned().await),
            None => None,
        };
        let lookup_time = ValidationTime::now();
        if let Some(cached) = self
            .cached_authenticated_zone_backend(&key, lookup_time)
            .await?
        {
            return Ok(ChainStatus::Secure {
                keys: cached.keys,
                deadline: cached.deadline,
                cached: true,
                valid_until: cached.valid_until,
            });
        }
        let mut ancestor = None;
        let result = self
            .authenticate_zone_uncached(zone, class, time, false, &mut ancestor)
            .await;
        drop(_gate);
        if matches!(result, Err(ResolveError::DnssecBogus(_)))
            && let Some(ancestor) = ancestor
            && let Ok(Some(_)) = self.refresh_authenticated_zone(&ancestor).await
        {
            let _retry_gate = match self.authenticated_zones.gate(&key) {
                Some(gate) => Some(gate.lock_owned().await),
                None => None,
            };
            return self
                .authenticate_zone_uncached(zone, class, ValidationTime::now(), false, &mut None)
                .await;
        }
        result
    }

    /// At most one refresh per cached zone/interval, under the same acquisition
    /// gate. A newer set installed by another request can be retried directly.
    pub(super) async fn refresh_authenticated_zone(
        &self,
        used: &Arc<AuthenticatedDnskeySet>,
    ) -> Result<Option<RefreshedZone>, ResolveError> {
        let key = self.zone_cache_key(used.zone(), used.class())?;
        let _gate = match self.authenticated_zones.gate(&key) {
            Some(gate) => Some(gate.lock_owned().await),
            None => None,
        };
        let now = ValidationTime::now();
        if let Some(current) = self.cached_authenticated_zone_backend(&key, now).await? {
            if !Arc::ptr_eq(&current.keys, used) {
                return Ok(Some(RefreshedZone {
                    keys: current.keys,
                    deadline: current.deadline,
                    at: now,
                    signature_ttl: current.valid_until.wrapping_sub(now.unix),
                }));
            }
            if !self
                .allow_authenticated_refresh_backend(&key, used, now)
                .await?
            {
                return Ok(None);
            }
        }
        // An expired/evicted set is a normal miss, not a reusable failure.
        match self
            .authenticate_zone_uncached(&key.zone, key.class, now, true, &mut None)
            .await?
        {
            ChainStatus::Secure {
                keys,
                deadline,
                valid_until,
                ..
            } => {
                let at = ValidationTime::now();
                Ok(Some(RefreshedZone {
                    keys,
                    deadline,
                    at,
                    signature_ttl: valid_until.wrapping_sub(at.unix),
                }))
            }
            // A failed rollover refresh cannot turn trusted data into an
            // insecure success. The original validation error must survive.
            ChainStatus::Insecure { .. } => Ok(None),
        }
    }

    async fn authenticate_zone_uncached(
        &self,
        zone: &DomainName,
        class: ClassType,
        time: ValidationTime,
        force: bool,
        cached_ancestor: &mut Option<Arc<AuthenticatedDnskeySet>>,
    ) -> Result<ChainStatus, ResolveError> {
        let anchor = self.zone_cache_key(zone, class)?.anchor;
        let (base, links) = self
            .delegation_path(zone, class, &anchor, force, cached_ancestor)
            .await?;
        let reused_zone = base.is_some() && links.is_empty();
        let base = match base {
            Some(base) => base,
            None => self.authenticate_anchor(&anchor, class, time).await?,
        };
        // Zero TTL can authenticate this transaction. Signature time separately
        // prevents slow acquisition from accepting an expired later link.
        let mut chain = ChainValidation {
            signature_ttl: base.valid_until.wrapping_sub(time.unix),
            keys: base.keys,
            ttl: base.ttl,
            deadline: base.deadline,
            time,
            class,
            anchor,
        };
        for link in links.into_iter().rev() {
            if !link.has_ds {
                return self.authenticate_unsigned_link(&chain, &link);
            }
            if let Some(insecure) = self.authenticate_child(&mut chain, link).await? {
                return Ok(insecure);
            }
        }
        check_signature_time(time, chain.signature_ttl)?;
        Ok(ChainStatus::Secure {
            keys: chain.keys,
            deadline: chain.deadline,
            cached: reused_zone,
            valid_until: time.unix.wrapping_add(chain.signature_ttl),
        })
    }

    pub(super) async fn discover_zone(
        &self,
        name: &DomainName,
        class: ClassType,
    ) -> Result<DomainName, ResolveError> {
        let response = self
            .resolve_dnssec_material(Question {
                qname: name.clone(),
                qtype: QueryType::SOA,
                qclass: QClassType::Class(class),
            })
            .await?;
        closest_soa_owner(&response, name, class).ok_or(ResolveError::DnssecIndeterminate(
            DnssecValidationError::MissingDenialProof,
        ))
    }

    async fn resolve_dnssec_material(&self, question: Question) -> Result<Message, ResolveError> {
        self.resolve_iteratively(question, None, Arc::new(AlgorithmSignals::default()), false)
            .await
            .map(|outcome| outcome.response)
    }
}

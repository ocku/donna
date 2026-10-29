//! One recovery owner can lend bounded, deduplicated parent work to NS subtasks.
mod cache;
use super::{Resolver, state_machine::ResolutionState};
use crate::ResolveError;
use dns::{ClassType, DomainName, QClassType, Question};
use std::{
    hash::{Hash, Hasher},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use transport::Transport;

#[derive(Clone, Debug)]
pub(super) struct RecoveryGrant {
    zone: DomainName,
    token: u64,
    class: ClassType,
    checking_disabled: bool,
    questions: Arc<Mutex<Vec<Question>>>,
    committed: Arc<AtomicBool>,
}
impl PartialEq for RecoveryGrant {
    fn eq(&self, other: &Self) -> bool {
        self.zone == other.zone
            && self.token == other.token
            && self.class == other.class
            && self.checking_disabled == other.checking_disabled
    }
}
impl Eq for RecoveryGrant {}
impl Hash for RecoveryGrant {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.zone.hash(h);
        self.token.hash(h);
        self.class.hash(h);
        self.checking_disabled.hash(h);
    }
}
fn same_question(a: &Question, b: &Question) -> bool {
    a.qname.eq_dns(&b.qname) && a.qtype == b.qtype && a.qclass == b.qclass
}
impl RecoveryGrant {
    fn matches(&self, zone: &DomainName, class: ClassType, checking_disabled: bool) -> bool {
        self.zone.eq_dns(zone) && self.class == class && self.checking_disabled == checking_disabled
    }

    fn admit(&self, question: &Question, maximum: usize) -> bool {
        let mut questions = self.questions.lock().unwrap_or_else(|e| e.into_inner());
        if question.qclass != QClassType::Class(self.class)
            || questions.len() >= maximum
            || questions.iter().any(|q| same_question(q, question))
        {
            return false;
        }
        questions.push(question.clone());
        true
    }
}

pub(super) struct RecoveryAttempt {
    zone: DomainName,
    grant: Option<RecoveryGrant>,
    owner: bool,
    attempted: bool,
}

impl<T: Transport> Resolver<T> {
    pub(super) async fn prepare_delegation_recovery(
        &self,
        state: &mut ResolutionState<'_>,
    ) -> Result<(), ResolveError> {
        let zone = &state.current_delegation_zone;
        if zone.as_ref().is_empty() || state.recovery.iter().any(|r| r.zone.eq_dns(zone)) {
            return Ok(());
        }
        let QClassType::Class(class) = state.active_question.qclass else {
            return Ok(());
        };
        let cd = state.algorithm_signals.checking_disabled;
        let inherited = state
            .algorithm_signals
            .recovery_grants
            .iter()
            .find(|g| g.matches(zone, class, cd))
            .cloned();
        // No failed candidate: initial glueless A/AAAA discovery is ordinary bootstrap.
        if !state.zone_attempted && inherited.is_none() {
            return Ok(());
        }
        let owner = inherited.is_none();
        let grant = if let Some(grant) = inherited {
            Some(grant)
        } else {
            self.claim_delegation_refresh_backend(zone, class, cd)
                .await?
                .map(|token| RecoveryGrant {
                    zone: zone.clone(),
                    token,
                    class,
                    checking_disabled: cd,
                    questions: Arc::new(Mutex::new(Vec::new())),
                    committed: Arc::new(AtomicBool::new(false)),
                })
        };
        if owner && let Some(grant) = &grant {
            Arc::make_mut(&mut state.algorithm_signals)
                .recovery_grants
                .push(grant.clone());
        }
        state.recovery.push(RecoveryAttempt {
            zone: zone.clone(),
            grant,
            owner,
            attempted: false,
        });
        Ok(())
    }

    pub(super) async fn permit_ancestor_refresh(
        &self,
        state: &mut ResolutionState<'_>,
    ) -> Result<bool, ResolveError> {
        self.prepare_delegation_recovery(state).await?;
        let zone = &state.current_delegation_zone;
        if zone.as_ref().is_empty() {
            return Ok(true);
        }
        let QClassType::Class(class) = state.active_question.qclass else {
            return Ok(false);
        };
        let cd = state.algorithm_signals.checking_disabled;
        if let Some(attempt) = state.recovery.iter_mut().find(|r| r.zone.eq_dns(zone)) {
            if attempt.attempted {
                return Ok(false);
            }
            attempt.attempted = true;
            let Some(grant) = &attempt.grant else {
                return Ok(false);
            };
            if !grant.admit(&state.active_question, usize::from(self.config.max_steps)) {
                return Ok(false);
            }
            let admitted = self
                .start_delegation_refresh_backend(zone, class, cd, grant.token)
                .await?;
            if admitted {
                grant.committed.store(true, Ordering::Release);
            }
            return Ok(admitted);
        }
        // A missing in-bailiwick address may bootstrap at the parent before any
        // endpoint failed, but never impersonates another operation's recovery owner.
        if state
            .bootstraps
            .iter()
            .any(|(z, q)| z.eq_dns(zone) && same_question(q, &state.active_question))
        {
            return Ok(false);
        }
        let status = self
            .cache_select_for(&[super::engine::zone(zone, class)], |context| {
                Ok(context.delegation_cache.refresh_status(zone, class, cd))
            })
            .await?;
        if let Some(failed) = status {
            return if failed {
                Err(ResolveError::CachedDelegationFailure)
            } else {
                Err(ResolveError::DelegationRefreshInProgress)
            };
        }
        state
            .bootstraps
            .push((zone.clone(), state.active_question.clone()));
        Ok(true)
    }

    pub(super) async fn finish_failed_delegation_recovery(
        &self,
        state: &mut ResolutionState<'_>,
    ) -> Result<(), ResolveError> {
        let QClassType::Class(class) = state.active_question.qclass else {
            return Ok(());
        };
        let cd = state.algorithm_signals.checking_disabled;
        let grants: Vec<_> = state
            .recovery
            .iter()
            .filter(|r| r.owner)
            .filter_map(|r| r.grant.clone())
            .collect();
        if grants.is_empty() {
            return Ok(());
        }
        let scopes = if self.cache_engine.is_some() {
            grants
                .iter()
                .map(|g| super::engine::zone(&g.zone, class))
                .collect()
        } else {
            Vec::new()
        };
        self.cache_transaction_for(&scopes, |context| {
            for grant in &grants {
                // At least one actual ancestor start must have committed.
                if grant.committed.load(Ordering::Acquire) {
                    context.delegation_cache.finish_refresh_failure(
                        &grant.zone,
                        class,
                        cd,
                        grant.token,
                        context.config.failure_ttl,
                    );
                }
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn record_delegation_success(
        &self,
        state: &mut ResolutionState<'_>,
    ) -> Result<(), ResolveError> {
        if state.current_delegation_zone.as_ref().is_empty() {
            return Ok(());
        }
        let QClassType::Class(class) = state.active_question.qclass else {
            return Ok(());
        };
        let cd = state.algorithm_signals.checking_disabled;
        let zone = state.current_delegation_zone.clone();
        let owner = state
            .recovery
            .iter()
            .filter(|r| r.owner)
            .find(|r| r.zone.eq_dns(&zone))
            .and_then(|r| r.grant.as_ref().map(|g| g.token));
        if state.address_lookup && owner.is_none() {
            return Ok(());
        }
        let child_availability = !state.address_lookup;
        self.cache_transaction_for(&[super::engine::zone(&zone, class)], |context| {
            context
                .delegation_cache
                .refresh_succeeded(&zone, class, cd, owner, child_availability);
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::QueryType;
    #[test]
    fn grant_scope_and_bounded_question_ledger_do_not_cross_class_or_cd() {
        let zone = DomainName::from_dotted("example.test.").unwrap();
        let grant = RecoveryGrant {
            zone: zone.clone(),
            token: 7,
            class: ClassType::CH,
            checking_disabled: true,
            questions: Arc::new(Mutex::new(Vec::new())),
            committed: Arc::new(AtomicBool::new(false)),
        };
        assert!(grant.matches(&zone, ClassType::CH, true));
        assert!(
            !grant.matches(&zone, ClassType::IN, true),
            "IN NS-address work must not borrow CH owner"
        );
        assert!(!grant.matches(&zone, ClassType::CH, false));
        let mut q = Question {
            qname: DomainName::from_dotted("NS.EXAMPLE.TEST.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::CH),
        };
        assert!(grant.admit(&q, 2));
        assert!(
            !grant.committed.load(Ordering::Acquire),
            "reservation does not prove a committed start"
        );
        q.qname = DomainName::from_dotted("ns.example.test.").unwrap();
        assert!(!grant.admit(&q, 2));
        q.qtype = QueryType::AAAA;
        assert!(grant.admit(&q, 2));
        q.qname = DomainName::from_dotted("other.example.test.").unwrap();
        assert!(!grant.admit(&q, 2));
    }
    #[tokio::test]
    async fn owned_ns_address_progress_retires_a_before_child_b_failure_borrowed_lease_survives() {
        for owner in [true, false] {
            let zone = DomainName::from_dotted("example.test.").unwrap();
            let q = Question {
                qname: DomainName::from_dotted("ns.foo.example.test.").unwrap(),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            };
            let resolver = Resolver::new(
                crate::resolver::tests::ancestor::Hierarchy::new(),
                crate::ResolverConfig::default(),
            );
            // No NS routing data: A's completed recovery must not become a TTL0 tombstone after B fails.
            let token = resolver
                .delegation_cache
                .claim_refresh(
                    &zone,
                    ClassType::IN,
                    false,
                    std::time::Duration::from_secs(1),
                )
                .unwrap();
            assert!(resolver.delegation_cache.start_refresh(
                &zone,
                ClassType::IN,
                false,
                token,
                std::time::Duration::from_secs(1)
            ));
            let grant = RecoveryGrant {
                zone: zone.clone(),
                token,
                class: ClassType::IN,
                checking_disabled: false,
                questions: Arc::new(Mutex::new(vec![q.clone()])),
                committed: Arc::new(AtomicBool::new(true)),
            };
            let mut state = ResolutionState {
                active_question: q.clone(),
                cname_answers: vec![],
                cname_authorities: vec![],
                proof_deadlines: Default::default(),
                cname_names: crate::name::NameSet::default(),
                current_delegation_zone: zone.clone(),
                candidates: vec![],
                pending_name_servers: vec![],
                restart_from_root: false,
                zone_attempted: true,
                address_lookup: true,
                bootstraps: vec![],
                recovery: vec![RecoveryAttempt {
                    zone: zone.clone(),
                    grant: Some(grant),
                    owner,
                    attempted: true,
                }],
                attempts: Arc::new(Mutex::new(
                    super::super::retry_budget::RetryBudget::default(),
                )),
                reachable_dns_error: false,
                cname_loop_seen: false,
                deferred_address_error: None,
                used_cached_delegation: false,
                algorithm_signals: Arc::new(super::super::AlgorithmSignals::default()),
                cache_allowed: true,
                validated_dnames_allowed: false,
            };
            // The actual accepted-referral path calls this before changing A to B.
            resolver
                .record_delegation_success(&mut state)
                .await
                .unwrap();
            state.current_delegation_zone = DomainName::from_dotted("foo.example.test.").unwrap();
            resolver
                .finish_failed_delegation_recovery(&mut state)
                .await
                .unwrap();
            assert!(
                !resolver.delegation_cache.failed_without_routes(&q, false),
                "A succeeded before B failed; owner={owner}"
            );
            assert_eq!(
                resolver
                    .delegation_cache
                    .refresh_status(&zone, ClassType::IN, false),
                if owner { None } else { Some(false) },
                "borrowed outer ownership must remain intact"
            );
        }
    }
}

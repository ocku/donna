use super::AlgorithmSignals;

pub(super) mod ancestor;
mod ancestor_parent;
mod cache_coherence;
mod coalescing;
mod failure;
mod ns_failure;
mod referral;
mod retry_limit;
mod work_limit;

include!("support.rs");

mod caching_and_retry;
mod cname_resolution;
mod delegation_boundaries;
mod dname_edns;
mod edns;
mod negative_and_delegation;
mod negative_cache_and_boundaries;
mod normalization_and_limits;
mod retry_and_cache;
mod routing_and_races;
mod validation_and_transport;

pub(super) mod external_backend;

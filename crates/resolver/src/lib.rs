//! Resolve DNS questions iteratively from roots or through configured recursive peers.
//!
//! The iterative resolver accepts concrete DNS classes. It doesn't support `QCLASS=ANY`,
//! unknown classes, or zone-transfer operations.

#![deny(missing_docs)]

mod cache;
mod config;
mod error;
mod forwarder;
mod name;
mod protocol;
mod resolver;
mod response;
mod root_hints;
mod server;
mod stats;

pub use cache::engine::{
    CacheCategory, CacheEngine, CacheEngineConfig, CacheEntryFamily, CacheEntryKey, CacheMutation,
    CacheMutationBatch, CacheRead, CacheReadPlan, CacheReadResult, CacheReadSet, SealedCacheEntry,
};
pub use config::ResolverConfig;
pub use error::ResolveError;
pub use forwarder::{Forwarder, ForwarderConfig};
pub use resolver::Resolver;
pub use server::RecursiveServer;
pub use stats::{ResolutionCacheSource, ResolutionResult, ResolutionStats};

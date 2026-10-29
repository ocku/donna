use std::{future::Future, pin::Pin};

/// A borrowed, sendable future for Donna's object-safe asynchronous interfaces.
///
/// Implementations normally return `Box::pin(async move { ... })`. Work inside
/// that block starts when polled. Dropping the future drops its owned state;
/// implementations that spawn tasks must define their own cancellation policy.
/// The lifetime permits borrowed requests and backends without requiring them
/// to be `'static`. No procedural macro is needed to implement these interfaces.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(test)]
mod tests;

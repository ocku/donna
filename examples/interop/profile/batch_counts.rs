//! Private copied-source instrumentation; never linked into production.
use std::sync::atomic::{AtomicU64, Ordering};

static RX: [AtomicU64; 17] = [const { AtomicU64::new(0) }; 17];
static DISPATCH: [AtomicU64; 17] = [const { AtomicU64::new(0) }; 17];
static SEND: [AtomicU64; 17] = [const { AtomicU64::new(0) }; 17];
static COUNTS: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];

pub(super) const RX_CALL: usize = 0;
pub(super) const RX_WOULD_BLOCK: usize = 1;
pub(super) const RX_INTERRUPTED: usize = 2;
pub(super) const SYNC_SOME: usize = 3;
pub(super) const SYNC_NONE: usize = 4;
pub(super) const DEFERRED: usize = 5;
pub(super) const DEFERRED_READY: usize = 6;
pub(super) const DEFERRED_PENDING: usize = 7;
pub(super) const PREPARED: usize = 8;
pub(super) const FIRST_ATTEMPT: usize = 9;
pub(super) const FIRST_SENT: usize = 10;
pub(super) const FIRST_WOULD_BLOCK: usize = 11;
pub(super) const FIRST_ERROR: usize = 12;
pub(super) const FIRST_EXPIRED: usize = 13;
pub(super) const SEND_COMMITTED: usize = 14;
pub(super) const SEND_ERROR: usize = 15;

#[inline]
pub(super) fn add(index: usize) { COUNTS[index].fetch_add(1, Ordering::Relaxed); }
#[inline]
pub(super) fn received(count: usize) { RX[count].fetch_add(1, Ordering::Relaxed); }
#[inline]
pub(super) fn dispatch(count: usize) { DISPATCH[count].fetch_add(1, Ordering::Relaxed); }
#[inline]
pub(super) fn send(count: usize) { SEND[count].fetch_add(1, Ordering::Relaxed); }
#[inline]
pub(super) fn committed(count: usize) { COUNTS[SEND_COMMITTED].fetch_add(count as u64, Ordering::Relaxed); }

fn array(values: &[AtomicU64]) -> String {
    let values: Vec<_> = values.iter().map(|v| v.load(Ordering::Relaxed).to_string()).collect();
    format!("[{}]", values.join(","))
}

pub(crate) fn snapshot() -> String {
    let names = ["rx_calls", "rx_would_block", "rx_interrupted", "sync_some", "sync_none",
                 "deferred", "deferred_ready", "deferred_pending", "prepared", "first_attempt",
                 "first_sent", "first_would_block", "first_error", "first_expired", "send_committed", "send_error"];
    let counts: Vec<_> = names.iter().zip(COUNTS.iter()).map(|(name, value)| {
        format!("\"{name}\":{}", value.load(Ordering::Relaxed))
    }).collect();
    format!("{{\"rx\":{},\"dispatch\":{},\"send\":{},\"counts\":{{{}}}}}",
            array(&RX), array(&DISPATCH), array(&SEND), counts.join(","))
}

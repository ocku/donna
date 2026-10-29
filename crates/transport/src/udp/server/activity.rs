//! Packet admission activity counters shared by UDP server tests.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
pub(in crate::udp) struct PacketActivity {
    received: AtomicUsize,
    active: AtomicUsize,
    pub(in crate::udp) maximum: AtomicUsize,
    changed: Notify,
}

impl PacketActivity {
    pub(in crate::udp) fn record_received(&self) {
        self.received.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    pub(super) fn start(activity: Arc<Self>) -> PacketActivityGuard {
        let active = activity.active.fetch_add(1, Ordering::SeqCst) + 1;
        activity.maximum.fetch_max(active, Ordering::SeqCst);
        activity.changed.notify_waiters();
        PacketActivityGuard(activity)
    }

    #[cfg(test)]
    pub(in crate::udp) async fn wait_for_received(&self, expected: usize) {
        loop {
            let notified = self.changed.notified();
            if self.received.load(Ordering::SeqCst) >= expected {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(in crate::udp) async fn wait_for_active(&self, expected: usize) {
        loop {
            let notified = self.changed.notified();
            if self.active.load(Ordering::SeqCst) == expected {
                return;
            }
            notified.await;
        }
    }
}

pub(super) struct PacketActivityGuard(Arc<PacketActivity>);

impl Drop for PacketActivityGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

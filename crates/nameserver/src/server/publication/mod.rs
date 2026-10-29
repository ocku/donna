use std::sync::Arc;

use dns::{ClassType, DomainName, RData, SerialNumber};
use tokio::sync::Mutex;
use tracing::{debug, instrument};

use crate::{Zone, name::dns_name_key};

use super::{IxfrDelta, NameServer};

#[cfg(test)]
mod tests;

/// Describes how an accepted zone installation affected published state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// A zone for a previously unknown apex and class was installed.
    Installed,
    /// A changed zone replaced an older snapshot with a newer RFC 1982 serial.
    Replaced,
    /// The supplied snapshot was identical to the installed snapshot.
    Unchanged,
    /// A changed snapshot was rejected because its SOA serial was not newer.
    StaleSerial,
}

/// Indicates a task failure, storage failure, or exhausted publication conflicts.
#[derive(Debug)]
pub struct InstallError(super::ZoneStoreError);

impl std::fmt::Display for InstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "zone installation failed: {}", self.0)
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl NameServer {
    /// Publishes a validated zone snapshot and reports task or backend failure.
    ///
    /// A changed zone with the same apex and class replaces the installed
    /// snapshot only when its SOA serial is newer under RFC 1982.
    ///
    /// # Errors
    ///
    /// Returns an error if the server-owned task is cancelled or panics, the
    /// backend fails, or 32 consecutive catalog revision conflicts prevent
    /// publication. Dropping the caller does not cancel that task.
    #[instrument(level = "debug", skip(self, zone), fields(zone_apex = ?zone.apex()))]
    pub async fn install(&self, zone: Zone) -> Result<InstallOutcome, InstallError> {
        // Installation is owned by the server once requested. Dropping the
        // caller must not strand a published snapshot between publication,
        // journal maintenance, and NOTIFY scheduling.
        let server = self.clone();
        let task = tokio::spawn(async move { server.install_owned(zone).await });
        task.await.map_err(|error| InstallError(Box::new(error)))?
    }

    async fn install_owned(&self, zone: Zone) -> Result<InstallOutcome, InstallError> {
        let mutation = self.zone_mutation_lock(zone.apex(), zone.class()).await;
        let _mutation_guard = mutation.lock_owned().await;
        let zone = Arc::new(zone);
        if let super::storage::ZoneStorage::External(store) = &self.zones {
            // Re-read the whole catalog after conflicts so concurrent changes
            // to unrelated zones can never be lost.
            for _ in 0..32 {
                let snapshot = store.snapshot().await.map_err(InstallError)?;
                let previous = snapshot
                    .zones()
                    .find(|old| old.apex().eq_dns(zone.apex()) && old.class() == zone.class())
                    .cloned();
                if let Some(old) = &previous {
                    if old.has_same_snapshot(&zone) {
                        return Ok(InstallOutcome::Unchanged);
                    }
                    if !has_newer_serial(old, &zone) {
                        return Ok(InstallOutcome::StaleSerial);
                    }
                }
                let mut replacement: Vec<_> = snapshot
                    .zones()
                    .filter(|old| !(old.apex().eq_dns(zone.apex()) && old.class() == zone.class()))
                    .cloned()
                    .collect();
                replacement.push(Arc::clone(&zone));
                if !store
                    .compare_exchange(snapshot.revision(), &replacement)
                    .await
                    .map_err(InstallError)?
                {
                    continue;
                }
                if let Some(old) = previous {
                    self.record_ixfr_change(&old, &zone).await;
                    self.notify_zone_change(&zone).await;
                    return Ok(InstallOutcome::Replaced);
                }
                return Ok(InstallOutcome::Installed);
            }
            return Err(InstallError(
                "authoritative catalog remained conflicted after 32 attempts".into(),
            ));
        }
        let published = Arc::clone(&zone);
        let mut zones = self.zones.write().await;
        let zones_at_apex = zones.by_apex.entry(dns_name_key(zone.apex())).or_default();
        let (replaced, changed, previous) = if let Some(old) = zones_at_apex
            .iter_mut()
            .find(|old| old.class() == zone.class())
        {
            let changed = !old.has_same_snapshot(&zone);
            if !changed {
                return Ok(InstallOutcome::Unchanged);
            }
            if changed && !has_newer_serial(old, &zone) {
                debug!(
                    old_serial = soa_serial(old),
                    new_serial = soa_serial(&zone),
                    "ignored changed zone installation without a newer RFC 1982 serial"
                );
                return Ok(InstallOutcome::StaleSerial);
            }
            let previous = Arc::clone(old);
            *old = Arc::clone(&zone);
            (true, changed, Some(previous))
        } else {
            zones_at_apex.push(Arc::clone(&zone));
            zones.len += 1;
            (false, true, None)
        };
        debug!(replaced, zone_count = zones.len, "DNS zone installed");
        drop(zones);
        if replaced && changed {
            if let Some(previous) = previous {
                self.record_ixfr_change(previous.as_ref(), published.as_ref())
                    .await;
            }
            self.notify_zone_change(published.as_ref()).await;
        }
        Ok(if replaced {
            InstallOutcome::Replaced
        } else {
            InstallOutcome::Installed
        })
    }

    pub(super) async fn zone_mutation_lock(
        &self,
        apex: &DomainName,
        class: ClassType,
    ) -> Arc<Mutex<()>> {
        let key = (dns_name_key(apex), class.value());
        let mut mutations = self.zone_mutations.lock().await;
        Arc::clone(
            mutations
                .entry(key)
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    pub(super) async fn record_ixfr_change(&self, old: &Zone, new: &Zone) {
        let key = (dns_name_key(new.apex()), new.class().value());
        let mut histories = self.ixfr_history.lock().await;
        if self.config.max_ixfr_history == 0 {
            histories.remove(&key);
            return;
        }
        let history = histories.entry(key).or_default();
        let Some(delta) = IxfrDelta::between(old, new) else {
            history.clear();
            return;
        };
        if history
            .back()
            .is_some_and(|previous| previous.new_serial() != delta.old_serial())
        {
            history.clear();
        }
        history.push_back(delta);
        while history.len() > self.config.max_ixfr_history {
            history.pop_front();
        }
    }
}

fn has_newer_serial(old: &Zone, new: &Zone) -> bool {
    let (Some(old), Some(new)) = (soa_serial(old), soa_serial(new)) else {
        return false;
    };
    SerialNumber::new(old).compare(SerialNumber::new(new)) == Some(std::cmp::Ordering::Less)
}

fn soa_serial(zone: &Zone) -> Option<u32> {
    match zone.soa().rdata {
        RData::SOA { serial, .. } => Some(serial),
        _ => None,
    }
}

use std::sync::Arc;

use dns::RCode;
use tracing::{debug, warn};

use crate::{Zone, name::dns_name_key};

use super::super::{
    NameServer,
    storage::{ZoneSnapshot, ZoneStorage},
};

pub(super) async fn publish(
    server: &NameServer,
    current: &Zone,
    candidate: &Arc<Zone>,
    external_snapshot: Option<ZoneSnapshot>,
) -> RCode {
    if let (ZoneStorage::External(store), Some(snapshot)) = (&server.zones, external_snapshot) {
        let mut replacement: Vec<_> = snapshot
            .zones()
            .filter(|old| {
                !(old.apex().eq_dns(candidate.apex()) && old.class() == candidate.class())
            })
            .cloned()
            .collect();
        replacement.push(Arc::clone(candidate));
        match store
            .compare_exchange(snapshot.revision(), &replacement)
            .await
        {
            Ok(true) => {}
            Ok(false) => return RCode::ServerFailure,
            Err(error) => {
                warn!(%error, "failed to commit authoritative catalog");
                return RCode::ServerFailure;
            }
        }
    } else {
        let persistence = server
            .config
            .update_persistence
            .as_ref()
            .expect("built-in updates require persistence");
        if let Err(error) = persistence.persist(candidate.as_ref()).await {
            warn!(%error, "failed to persist dynamic update");
            return RCode::ServerFailure;
        }

        let mut zones = server.zones.write().await;
        let Some(published) = zones
            .by_apex
            .get_mut(&dns_name_key(candidate.apex()))
            .and_then(|at_apex| {
                at_apex
                    .iter_mut()
                    .find(|zone| zone.class() == candidate.class())
            })
        else {
            unreachable!("same-zone installation is serialized with dynamic update")
        };
        *published = Arc::clone(candidate);
        debug!(zone_apex = ?candidate.apex(), "dynamic update committed");
    }
    server.record_ixfr_change(current, candidate.as_ref()).await;
    server.notify_zone_change(candidate.as_ref()).await;
    RCode::Ok
}

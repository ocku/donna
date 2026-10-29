//! Cheap eligibility checks supplement the already authenticated cache rank.
use super::{Resolver, key_cache::ValidationTime};
use dns::{RData, ResourceRecord};
use transport::Transport;

impl<T: Transport> Resolver<T> {
    pub(in crate::resolver) fn cached_dnssec_context_live<'a>(
        &self,
        records: impl Iterator<Item = &'a ResourceRecord>,
    ) -> bool {
        let now = ValidationTime::now();
        for record in records {
            let RData::RRSIG(sig) = &record.rdata else {
                continue;
            };
            let lifetime = sig
                .signature_expiration
                .wrapping_sub(sig.signature_inception);
            if lifetime >= (1 << 31) || now.unix.wrapping_sub(sig.signature_inception) > lifetime {
                return false;
            }
            let Ok(key) = self.zone_cache_key(&sig.signer_name, record.class) else {
                return false;
            };
            let Some(zone) = self.authenticated_zones.get(&key, now) else {
                return false;
            };
            // This is only an eligibility veto, never proof of a signature:
            // complete validation supplied each admitted entry's AD rank.
            if !zone.keys.records().iter().any(|record| {
                matches!(&record.rdata,
                RData::DNSKEY(key) if key.algorithm == sig.algorithm && key.key_tag() == sig.key_tag
                    && key.protocol == 3 && key.flags & 0x100 != 0 && key.flags & 0x80 == 0)
            }) {
                return false;
            }
        }
        true
    }
}

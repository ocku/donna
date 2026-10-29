//! Walk toward a trust anchor, then authenticate the chain's base DNSKEY set.
use super::*;

const MAX_DELEGATION_LINKS: usize = 128;

impl<T: Transport> Resolver<T> {
    pub(super) async fn delegation_path(
        &self,
        zone: &DomainName,
        class: ClassType,
        anchor_zone: &DomainName,
        force: bool,
        cached_ancestor: &mut Option<Arc<AuthenticatedDnskeySet>>,
    ) -> Result<(Option<CachedZone>, Vec<DelegationLink>), ResolveError> {
        let mut child = zone.clone();
        let mut links = Vec::new();
        let mut base = None;
        loop {
            if !force {
                let key = ZoneKey {
                    zone: child.clone(),
                    class,
                    anchor: anchor_zone.clone(),
                };
                if let Some(cached) = self
                    .cached_authenticated_zone_backend(&key, ValidationTime::now())
                    .await?
                {
                    *cached_ancestor = Some(Arc::clone(&cached.keys));
                    base = Some(cached);
                    break;
                }
            }
            if child.eq_dns(anchor_zone) {
                break;
            }
            if links.len() >= MAX_DELEGATION_LINKS || !child.is_descendant_of(anchor_zone) {
                return Err(ResolveError::DnssecIndeterminate(
                    DnssecValidationError::MissingTrustAnchor,
                ));
            }
            let response = self
                .resolve_dnssec_material(Question {
                    qname: child.clone(),
                    qtype: QueryType::DS,
                    qclass: QClassType::Class(class),
                })
                .await?;
            let ds_records = records_at_type(&response.answers, &child, RecordType::DS, class);
            let has_ds = !ds_records.is_empty();
            // An unsigned parent (or a self-signed island) cannot identify its
            // authenticated signer. Walk toward the anchor until a validated
            // delegation proves insecurity; the untrusted links are still
            // validated normally if no such delegation exists.
            let parent = parent_signer(&response, &child, class)
                .filter(|parent| {
                    !parent.eq_dns(&child)
                        && child.is_descendant_of(parent)
                        && parent.is_descendant_of(anchor_zone)
                })
                .unwrap_or_else(|| {
                    DomainName::from_labels(child.as_ref()[1..].to_vec())
                        .expect("a non-anchor descendant has a parent")
                });
            links.push(DelegationLink {
                child,
                response,
                has_ds,
            });
            child = parent;
        }

        Ok((base, links))
    }

    pub(super) async fn authenticate_anchor(
        &self,
        anchor_zone: &DomainName,
        class: ClassType,
        time: ValidationTime,
    ) -> Result<CachedZone, ResolveError> {
        let now = time.unix;
        let anchors = self
            .config
            .trust_anchors
            .iter()
            .filter_map(|record| match &record.rdata {
                RData::DNSKEY(key) if record.class == class && record.name.eq_dns(anchor_zone) => {
                    Some(key.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let anchor_response = self
            .resolve_dnssec_material(Question {
                qname: anchor_zone.clone(),
                qtype: QueryType::DNSKEY,
                qclass: QClassType::Class(class),
            })
            .await?;
        let anchor_keys = records_at_type(
            &anchor_response.answers,
            anchor_zone,
            RecordType::DNSKEY,
            class,
        );
        let anchor_signatures = signatures_covering(
            &anchor_response.answers,
            anchor_zone,
            RecordType::DNSKEY,
            class,
        );
        let mut anchor_error = None;
        let mut authenticated_anchor = None;
        for anchor in &anchors {
            match authenticate_dnskey_with_anchor(
                anchor_zone,
                class,
                &anchor_keys,
                &anchor_signatures,
                anchor,
                now,
            ) {
                DnssecValidation::Secure(keys) => {
                    authenticated_anchor = Some(keys);
                    break;
                }
                DnssecValidation::Bogus(error) => {
                    anchor_error = Some(ResolveError::DnssecBogus(error));
                }
                DnssecValidation::Indeterminate(error) => {
                    if anchor_error.is_none() {
                        anchor_error = Some(ResolveError::DnssecIndeterminate(error));
                    }
                }
                DnssecValidation::Insecure => {}
            }
        }
        let keys = authenticated_anchor.ok_or_else(|| {
            anchor_error.unwrap_or(ResolveError::DnssecIndeterminate(
                DnssecValidationError::MissingTrustAnchor,
            ))
        })?;
        let chain_ttl = keys.authenticated_ttl();
        let keys = Arc::new(keys);
        let deadline = time
            .instant
            .checked_add(std::time::Duration::from_secs(u64::from(chain_ttl)))
            .unwrap_or(time.instant);
        self.insert_authenticated_zone_backend(
            ZoneKey {
                zone: anchor_zone.clone(),
                class,
                anchor: anchor_zone.clone(),
            },
            Arc::clone(&keys),
            AuthenticatedLifetime {
                ttl: chain_ttl,
                started: time,
                deadline,
                valid_until: keys.signature_expiration(),
            },
        )
        .await?;
        Ok(CachedZone {
            valid_until: keys.signature_expiration(),
            keys,
            ttl: chain_ttl,
            deadline,
        })
    }
}

//! Validate each link while retaining the narrowest TTL and signature interval.
use super::*;

impl<T: Transport> Resolver<T> {
    pub(super) fn authenticate_unsigned_link(
        &self,
        chain: &ChainValidation,
        link: &DelegationLink,
    ) -> Result<ChainStatus, ResolveError> {
        check_signature_time(chain.time, chain.signature_ttl)?;
        let denial_time = ValidationTime::now();
        let denial = self.validate_unsigned_delegation(
            &chain.keys,
            &link.child,
            &link.response,
            denial_time.unix,
        )?;
        let valid_until = chain.time.unix.wrapping_add(
            chain
                .signature_ttl
                .min(denial.signature_expiration().wrapping_sub(chain.time.unix)),
        );
        let deadline = chain.deadline.min(
            denial_time
                .instant
                .checked_add(std::time::Duration::from_secs(u64::from(
                    denial.authenticated_ttl(),
                )))
                .unwrap_or(denial_time.instant),
        );
        Ok(ChainStatus::Insecure {
            deadline,
            valid_until,
        })
    }

    pub(super) async fn authenticate_child(
        &self,
        chain: &mut ChainValidation,
        link: DelegationLink,
    ) -> Result<Option<ChainStatus>, ResolveError> {
        let ds_records = records_at_type(
            &link.response.answers,
            &link.child,
            RecordType::DS,
            chain.class,
        );
        let ds_signatures = signatures_covering(
            &link.response.answers,
            &link.child,
            RecordType::DS,
            chain.class,
        );
        let authenticated_ds = validation_result(chain.keys.validate_rrset(
            &ds_records,
            &ds_signatures,
            chain.time.unix,
        ))?;
        chain.ttl = chain.ttl.min(authenticated_ds.authenticated_ttl());
        chain.deadline = chain.deadline.min(
            chain
                .time
                .instant
                .checked_add(std::time::Duration::from_secs(u64::from(
                    authenticated_ds.authenticated_ttl(),
                )))
                .unwrap_or(chain.time.instant),
        );
        chain.signature_ttl = chain.signature_ttl.min(
            authenticated_ds
                .signature_expiration()
                .wrapping_sub(chain.time.unix),
        );
        let ds = ds_records
            .iter()
            .filter_map(|record| match &record.rdata {
                RData::DS(ds) => Some(ds.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let (dnskeys, signatures) = self.child_dnskeys(&link.child, chain.class).await?;
        match authenticate_dnskey_with_ds(
            &link.child,
            chain.class,
            &dnskeys,
            &signatures,
            &ds,
            chain.time.unix,
        ) {
            DnssecValidation::Secure(child_keys) => {
                chain.ttl = chain.ttl.min(child_keys.authenticated_ttl());
                chain.deadline = chain.deadline.min(
                    chain
                        .time
                        .instant
                        .checked_add(std::time::Duration::from_secs(u64::from(
                            child_keys.authenticated_ttl(),
                        )))
                        .unwrap_or(chain.time.instant),
                );
                chain.signature_ttl = chain.signature_ttl.min(
                    child_keys
                        .signature_expiration()
                        .wrapping_sub(chain.time.unix),
                );
                chain.keys = Arc::new(child_keys);
                self.insert_authenticated_zone_backend(
                    ZoneKey {
                        zone: link.child,
                        class: chain.class,
                        anchor: chain.anchor.clone(),
                    },
                    Arc::clone(&chain.keys),
                    AuthenticatedLifetime {
                        ttl: chain.ttl,
                        started: chain.time,
                        deadline: chain.deadline,
                        valid_until: chain.time.unix.wrapping_add(chain.signature_ttl),
                    },
                )
                .await?;
            }
            DnssecValidation::Insecure => {
                check_signature_time(chain.time, chain.signature_ttl)?;
                return Ok(Some(ChainStatus::Insecure {
                    deadline: chain.deadline,
                    valid_until: chain.time.unix.wrapping_add(chain.signature_ttl),
                }));
            }
            DnssecValidation::Bogus(error) => return Err(ResolveError::DnssecBogus(error)),
            DnssecValidation::Indeterminate(error) => {
                return Err(ResolveError::DnssecIndeterminate(error));
            }
        }
        Ok(None)
    }

    async fn child_dnskeys(
        &self,
        child: &DomainName,
        class: ClassType,
    ) -> Result<(Vec<dns::ResourceRecord>, Vec<dns::ResourceRecord>), ResolveError> {
        let dnskey_response = self
            .resolve_dnssec_material(Question {
                qname: child.clone(),
                qtype: QueryType::DNSKEY,
                qclass: QClassType::Class(class),
            })
            .await?;
        let dnskeys = records_at_type(&dnskey_response.answers, child, RecordType::DNSKEY, class);
        let signatures =
            signatures_covering(&dnskey_response.answers, child, RecordType::DNSKEY, class);
        Ok((dnskeys, signatures))
    }
}

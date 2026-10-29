use super::*;

impl<T: Transport> ResponseValidator<'_, '_, T> {
    pub(super) async fn validate_answer(
        &mut self,
        rrset: Vec<ResourceRecord>,
    ) -> Result<(), ResolveError> {
        *self.cached_keys = None;
        let signatures = signatures_covering(
            &self.response.answers,
            &rrset[0].name,
            rrset[0].rtype,
            rrset[0].class,
        );
        let zone = match signatures.iter().find_map(signature_signer) {
            Some(zone) => zone,
            None => {
                self.resolver
                    .discover_zone(&rrset[0].name, self.class)
                    .await?
            }
        };
        self.resolver.check_answer_zone(
            &rrset[0].name,
            &zone,
            self.class,
            rrset[0].rtype == RecordType::DS,
        )?;
        let Some(secure) = self.authenticate(&zone).await? else {
            return Ok(());
        };
        let keys = &secure.keys;
        let deadline = secure.deadline;
        let validated_at = secure.validated_at;
        let now = validated_at.unix;
        let authenticated_ttl = secure.ttl;
        let authenticated = validation_result(keys.validate_rrset(&rrset, &signatures, now))?;
        let rrset_ttl = authenticated.authenticated_ttl().min(authenticated_ttl);
        let rrset_bound = Bound::records_since(
            validated_at,
            self.observed_at,
            authenticated.authenticated_ttl(),
            authenticated.signature_expiration(),
            deadline,
        )
        .cap_deadline(if rrset[0].rtype == RecordType::DNAME {
            self.dname_deadline
        } else {
            None
        });
        self.outcome.bounds.add(
            Target::Answer(rrset[0].name.clone(), rrset[0].rtype, rrset[0].class),
            rrset_bound,
        );
        clamp_rrset_ttl(
            &mut self.response.answers,
            &rrset[0].name,
            rrset[0].rtype,
            rrset[0].class,
            rrset_ttl,
        );
        if rrset[0].rtype == RecordType::DNAME {
            for binding in self.bindings.iter().filter(|binding| {
                binding.class == rrset[0].class && binding.dname_owner.eq_dns(&rrset[0].name)
            }) {
                self.outcome.bounds.add(
                    Target::Answer(
                        binding.cname_owner.clone(),
                        RecordType::CNAME,
                        binding.class,
                    ),
                    rrset_bound,
                );
                clamp_rrset_ttl(
                    &mut self.response.answers,
                    &binding.cname_owner,
                    RecordType::CNAME,
                    binding.class,
                    rrset_ttl,
                );
            }
        }
        if let Some(closest_encloser) = authenticated.wildcard_closest_encloser() {
            self.validate_wildcard(keys, &rrset[0], closest_encloser, &secure)?;
        }
        self.retain_dname(&rrset, &signatures, rrset_bound);
        Ok(())
    }

    fn retain_dname(
        &mut self,
        rrset: &[ResourceRecord],
        signatures: &[ResourceRecord],
        rrset_bound: Bound,
    ) {
        if rrset[0].rtype == RecordType::DNAME {
            // Every retained signature's received TTL also bounds
            // the projected RRset, even if verification selected
            // another valid signature with a longer lifetime.
            let raw_ttl = rrset
                .iter()
                .chain(signatures.iter())
                .map(|record| record.ttl)
                .min()
                .unwrap_or(0);
            let source_deadline = self
                .observed_at
                .checked_add(std::time::Duration::from_secs(u64::from(raw_ttl)))
                .unwrap_or(self.observed_at);
            self.outcome.secure_dnames.push(ValidatedDname {
                owner: rrset[0].name.clone(),
                class: rrset[0].class,
                deadline: rrset_bound.deadline().min(source_deadline),
            });
        }
    }

    fn validate_wildcard(
        &mut self,
        keys: &dns::AuthenticatedDnskeySet,
        record: &ResourceRecord,
        closest_encloser: &DomainName,
        secure: &SecureZone,
    ) -> Result<(), ResolveError> {
        let deadline = secure.deadline;
        let validated_at = secure.validated_at;
        let now = validated_at.unix;
        let authenticated_ttl = secure.ttl;
        let denial = self.resolver.validate_wildcard_denial(
            keys,
            &record.name,
            closest_encloser,
            self.response,
            now,
        )?;
        authority::retain_denial_keys(&mut self.authority_keys, self.response, &denial);
        let proof_bound = Bound::records_since(
            validated_at,
            self.observed_at,
            denial.authenticated_ttl(),
            denial.signature_expiration(),
            deadline,
        );
        self.outcome.bounds.add(
            Target::Answer(record.name.clone(), record.rtype, record.class),
            proof_bound,
        );
        self.outcome.bounds.add(Target::Denial, proof_bound);
        if record.rtype == RecordType::DNAME {
            for binding in self.bindings.iter().filter(|binding| {
                binding.class == record.class && binding.dname_owner.eq_dns(&record.name)
            }) {
                self.outcome.bounds.add(
                    Target::Answer(
                        binding.cname_owner.clone(),
                        RecordType::CNAME,
                        binding.class,
                    ),
                    proof_bound,
                );
                clamp_rrset_ttl(
                    &mut self.response.answers,
                    &binding.cname_owner,
                    RecordType::CNAME,
                    binding.class,
                    denial.authenticated_ttl().min(authenticated_ttl),
                );
            }
        }
        // The expanded answer depends on this proof for its
        // entire authenticated lifetime, including cache reuse.
        clamp_rrset_ttl(
            &mut self.response.answers,
            &record.name,
            record.rtype,
            record.class,
            denial.authenticated_ttl().min(authenticated_ttl),
        );
        if denial.opt_out() {
            self.outcome.status = DnssecSecurityStatus::Insecure;
            self.outcome.bounds.add(Target::WholeReply, proof_bound);
        }
        clamp_denial_ttl(
            &mut self.response.authorities,
            denial.authenticated_ttl().min(authenticated_ttl),
        );
        Ok(())
    }
}

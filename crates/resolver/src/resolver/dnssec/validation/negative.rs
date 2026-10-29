use super::*;

impl<T: Transport> ResponseValidator<'_, '_, T> {
    pub(super) async fn validate_negative(&mut self) -> Result<(), ResolveError> {
        *self.cached_keys = None;
        let negative_name = terminal_name(self.question, &self.response.answers);
        let zone = closest_soa_owner(self.response, &negative_name, self.class).ok_or(
            ResolveError::DnssecBogus(DnssecValidationError::MissingDenialProof),
        )?;
        self.resolver.check_answer_zone(
            &negative_name,
            &zone,
            self.class,
            self.question.qtype == QueryType::DS,
        )?;
        let Some(secure) = self.authenticate(&zone).await? else {
            return Ok(());
        };
        let keys = &secure.keys;
        let deadline = secure.deadline;
        let validated_at = secure.validated_at;
        let now = validated_at.unix;
        let authenticated_ttl = secure.ttl;
        self.authority_keys.push(authority::AuthorityKey(
            zone.clone(),
            RecordType::SOA,
            self.class,
        ));
        let proof_keys = if self.resolver.config.cache_capacity == 0
            || self.response.headers.rcode != dns::RCode::NameError
        {
            Arc::clone(keys)
        } else {
            Arc::new(keys.with_denial_validation_cache())
        };
        self.validate_negative_soa(&proof_keys, &zone, &secure)?;
        let denial = self.resolver.validate_negative_denial(
            &proof_keys,
            &negative_name,
            self.question.qtype.value(),
            self.response,
            now,
        )?;
        authority::retain_denial_keys(&mut self.authority_keys, self.response, &denial);
        if self.resolver.config.cache_capacity != 0
            && !denial.opt_out()
            && denial.kind() == dns::DnssecDenialKind::NameError
        {
            self.outcome.negative_keys = Some(crate::cache::negative::DenialKeys {
                original: Arc::downgrade(keys),
                memoized: proof_keys,
            });
        }
        let proof_bound = Bound::records_since(
            validated_at,
            self.observed_at,
            denial.authenticated_ttl(),
            denial.signature_expiration(),
            deadline,
        );
        self.outcome.bounds.add(Target::Denial, proof_bound);
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

    fn validate_negative_soa(
        &mut self,
        proof_keys: &dns::AuthenticatedDnskeySet,
        zone: &DomainName,
        secure: &SecureZone,
    ) -> Result<(), ResolveError> {
        let validated_at = secure.validated_at;
        let deadline = secure.deadline;
        let authenticated_ttl = secure.ttl;
        let now = validated_at.unix;
        let soa = self
            .response
            .authorities
            .iter()
            .filter(|record| {
                record.rtype == RecordType::SOA
                    && record.class == self.class
                    && record.name.eq_dns(zone)
            })
            .cloned()
            .collect::<Vec<_>>();
        let soa_signatures = signatures_covering(
            &self.response.authorities,
            zone,
            RecordType::SOA,
            self.class,
        );
        let authenticated_soa =
            validation_result(proof_keys.validate_rrset(&soa, &soa_signatures, now))?;
        self.outcome.bounds.add(
            Target::Authority(zone.clone(), RecordType::SOA, self.class),
            Bound::records_since(
                validated_at,
                self.observed_at,
                authenticated_soa.authenticated_ttl(),
                authenticated_soa.signature_expiration(),
                deadline,
            ),
        );
        clamp_rrset_ttl(
            &mut self.response.authorities,
            zone,
            RecordType::SOA,
            self.class,
            authenticated_soa.authenticated_ttl().min(authenticated_ttl),
        );
        Ok(())
    }
}

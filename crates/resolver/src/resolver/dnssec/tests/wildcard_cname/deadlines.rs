use super::*;

#[derive(Clone)]
struct DelayedTargetKeys(SplitTransport);

impl Transport for DelayedTargetKeys {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            if query.questions[0].qtype == QueryType::DNSKEY
                && query.questions[0].qname.eq_dns(&name(&["other"]))
            {
                tokio::time::sleep(Duration::from_millis(3100)).await;
            }
            self.0.exchange(server, query, timeout).await
        })
    }
}

#[tokio::test]
async fn later_target_chain_cannot_cache_an_expired_earlier_cname_signature() {
    for ttl_only in [false, true] {
        let (original, question, _) = fixture(true);
        let config = original.config.clone();
        let mut source = Arc::try_unwrap(original.transport).ok().unwrap();
        // Replace the wildcard hop with an ordinary, genuinely signed CNAME at
        // the same question owner. Its signature expires during target acquisition.
        let mut rng = TestRng(0x5892_1234_5678_abcd);
        let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let key =
            RsaDnssecSigningKey::from_pkcs8_der(257, 8, private.to_pkcs8_der().unwrap().as_bytes())
                .unwrap();
        let now = crate::resolver::dnssec::unix_time();
        let record = source
            .alias
            .answers
            .iter()
            .find(|record| record.rtype == RecordType::CNAME)
            .unwrap()
            .clone();
        let signature = key
            .sign_rrset(
                std::slice::from_ref(&record),
                &name(&["example"]),
                now.wrapping_sub(60),
                now.wrapping_add(if ttl_only { 3600 } else { 2 }),
            )
            .unwrap();
        let mut signed = source
            .alias
            .answers
            .iter()
            .find(|record| record.rtype == RecordType::RRSIG)
            .unwrap()
            .clone();
        signed.rdata = RData::RRSIG(signature);
        source.alias.answers = vec![record, signed];
        source.alias.authorities.clear();
        let requests = Arc::clone(&source.requests);
        if ttl_only {
            for record in &mut source.keys[0].answers {
                record.ttl = 1;
            }
        }
        let resolver = Resolver::new(DelayedTargetKeys(source), config);
        if ttl_only {
            resolver
                .authenticate_zone(
                    &name(&["example"]),
                    ClassType::IN,
                    crate::resolver::dnssec::unix_time(),
                )
                .await
                .unwrap();
            let reply = resolver.resolve(question).await.unwrap();
            assert!(reply.headers.ad);
            assert!(
                reply
                    .answers
                    .iter()
                    .any(|record| record.rtype == RecordType::CNAME && record.ttl == 0)
            );
            assert!(
                reply
                    .answers
                    .iter()
                    .any(|record| record.rtype == RecordType::A && record.ttl > 0)
            );
            assert_eq!(
                *requests.lock().unwrap(),
                4,
                "the first zone must reuse its authenticated keys"
            );
            continue;
        }
        assert!(matches!(
            resolver.resolve(question.clone()).await,
            Err(crate::ResolveError::DnssecBogus(
                dns::DnssecValidationError::Signature(dns::RrsigVerificationError::BadTime)
            ))
        ));
        assert!(resolver.positive_cache.get_question(&question).is_none());
    }
}

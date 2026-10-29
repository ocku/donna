use std::{net::SocketAddr, time::Duration};

use dns::{ClassType, Message, QueryType, RData, RecordType};
use transport::{Transport, TransportError};

use super::{
    fixtures,
    support::{InsecureTransport, name},
};
use crate::resolver::dnssec::chain::ChainStatus;

#[derive(Clone)]
struct DescendantTransport {
    ancestor: InsecureTransport,
    self_signed: bool,
}

impl Transport for DescendantTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let question = &query.questions[0];
            if question.qtype == QueryType::DS
                && question.qname.eq_dns(&name(&["sub", "child", "example"]))
            {
                let mut response = self.ancestor.ds.clone();
                response.headers.id = query.headers.id;
                response.headers.aa = true;
                response.questions.clone_from(&query.questions);
                response.authorities.clear();
                if self.self_signed {
                    let mut signature = self
                        .ancestor
                        .dnskey
                        .answers
                        .iter()
                        .find(|rr| rr.rtype == RecordType::RRSIG)
                        .unwrap()
                        .clone();
                    signature.name = question.qname.clone();
                    let RData::RRSIG(rrsig) = &mut signature.rdata else {
                        unreachable!()
                    };
                    rrsig.type_covered = u16::from(RecordType::DS);
                    rrsig.signer_name = question.qname.clone();
                    response.authorities.push(signature);
                }
                return Ok(response);
            }
            if question.qtype == QueryType::SOA {
                let mut response = self.ancestor.soa.clone();
                response.headers.id = query.headers.id;
                response.questions.clone_from(&query.questions);
                response.authorities[0].name = name(&["sub", "child", "example"]);
                return Ok(response);
            }
            self.ancestor.exchange(server, query, timeout).await
        })
    }
}

#[tokio::test]
async fn ancestor_unsigned_delegation_covers_unsigned_descendants_and_signature_islands() {
    for self_signed in [false, true] {
        let (ancestor, anchor, _) = fixtures::insecure_fixture();
        let resolver = fixtures::resolver(
            DescendantTransport {
                ancestor,
                self_signed,
            },
            anchor,
        );
        let result = resolver
            .authenticate_zone(
                &name(&["sub", "child", "example"]),
                ClassType::IN,
                super::super::unix_time(),
            )
            .await
            .unwrap();
        assert!(
            matches!(result, ChainStatus::Insecure { deadline, .. } if deadline.saturating_duration_since(std::time::Instant::now()).as_secs() <= 300)
        );
    }
}

#[tokio::test]
async fn missing_or_self_signed_proof_cannot_downgrade_a_secure_ancestor() {
    for self_signed in [false, true] {
        let (mut ancestor, anchor, _) = fixtures::insecure_fixture();
        // Remove the authenticated denial at child.example. No ancestor can
        // now establish insecurity for the unsigned descendant response.
        ancestor.ds.authorities.clear();
        ancestor.ds.headers.aa = true;
        let resolver = fixtures::resolver(
            DescendantTransport {
                ancestor,
                self_signed,
            },
            anchor,
        );
        let result = resolver
            .authenticate_zone(
                &name(&["sub", "child", "example"]),
                ClassType::IN,
                super::super::unix_time(),
            )
            .await;
        assert!(matches!(
            result,
            Err(crate::ResolveError::DnssecBogus(_) | crate::ResolveError::DnssecIndeterminate(_))
        ));
    }
}

#[tokio::test]
async fn unsigned_ds_rrset_under_secure_parent_is_rejected() {
    let (mut transport, anchor, _) = fixtures::delegated_fixture();
    transport
        .ds
        .answers
        .retain(|rr| rr.rtype != RecordType::RRSIG);
    let resolver = fixtures::resolver(transport, anchor);
    let result = resolver
        .authenticate_zone(
            &name(&["child", "example"]),
            ClassType::IN,
            super::super::unix_time(),
        )
        .await;
    assert!(matches!(
        result,
        Err(crate::ResolveError::DnssecBogus(_) | crate::ResolveError::DnssecIndeterminate(_))
    ));
}

#[tokio::test]
async fn unsigned_descendant_answers_resolve_and_cache_without_ad() {
    let (mut ancestor, anchor, mut question) = fixtures::insecure_fixture();
    question.qname = name(&["www", "sub", "child", "example"]);
    ancestor.answer.answers[0].name = question.qname.clone();
    let resolver = fixtures::resolver(
        DescendantTransport {
            ancestor,
            self_signed: false,
        },
        anchor,
    );
    let first = resolver.resolve(question.clone()).await.unwrap();
    assert!(!first.headers.ad);
    assert!(first.answers.iter().all(|rr| rr.ttl <= 300));
    let cached = resolver.resolve_with_stats(question).await.unwrap();
    assert!(!cached.response().headers.ad);
    assert!(cached.response().answers.iter().all(|rr| rr.ttl <= 300));
    assert_eq!(
        cached.stats().final_cache_source(),
        Some(crate::ResolutionCacheSource::Positive)
    );
}

#[tokio::test]
async fn unrelated_unsigned_signer_cannot_downgrade_an_answer() {
    let (mut transport, anchor, mut question) = fixtures::insecure_fixture();
    // child.example has a genuine authenticated unsigned delegation. It has
    // no authority over the victim in the secure parent zone.
    question.qname = name(&["www", "example"]);
    transport.answer.answers[0].name = question.qname.clone();
    let mut signature = transport.dnskey.answers[1].clone();
    signature.name = question.qname.clone();
    let RData::RRSIG(rrsig) = &mut signature.rdata else {
        unreachable!()
    };
    rrsig.type_covered = u16::from(RecordType::A);
    rrsig.signer_name = name(&["child", "example"]);
    transport.answer.answers.push(signature);
    let resolver = fixtures::resolver(transport, anchor);
    assert!(matches!(
        resolver.resolve(question).await,
        Err(crate::ResolveError::DnssecBogus(_))
    ));
}

#[tokio::test]
async fn claimed_zones_cannot_bypass_a_more_specific_answer_trust_anchor() {
    for mode in 0..3 {
        let (mut transport, anchor, mut question) = fixtures::insecure_fixture();
        let mut specific_anchor = anchor.clone();
        specific_anchor.name = name(&["sub", "child", "example"]);
        question.qname = name(&["www", "sub", "child", "example"]);
        transport.answer.answers[0].name = question.qname.clone();
        if mode == 0 {
            let mut signature = transport.dnskey.answers[1].clone();
            signature.name = question.qname.clone();
            let RData::RRSIG(rrsig) = &mut signature.rdata else {
                unreachable!()
            };
            rrsig.type_covered = u16::from(RecordType::A);
            rrsig.signer_name = name(&["child", "example"]);
            transport.answer.answers.push(signature);
        } else if mode == 2 {
            transport.answer.answers.clear();
            transport.answer.authorities = transport.soa.authorities.clone();
        }
        // mode 1 discovers the claimed SOA by query; mode 2 receives it as a
        // negative answer. Neither may override the local secure island.
        let resolver = crate::resolver::Resolver::new(
            transport,
            crate::ResolverConfig {
                root_servers: vec![(std::net::Ipv4Addr::LOCALHOST, 53).into()],
                trust_anchors: vec![anchor, specific_anchor],
                max_attempts_per_server: 1,
                ..crate::ResolverConfig::default()
            },
        );
        assert!(
            matches!(
                resolver.resolve(question).await,
                Err(crate::ResolveError::DnssecBogus(_))
            ),
            "mode {mode}"
        );
    }
}

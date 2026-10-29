use dns::{ClassType, QueryType, RData, RecordType};

use super::{fixtures, negative, support::name};
use crate::{ResolveError, ResolverConfig, resolver::Resolver};

fn with_child_anchor<T: transport::Transport>(
    transport: T,
    anchor: dns::ResourceRecord,
    owner: dns::DomainName,
) -> Resolver<T> {
    let mut child_anchor = anchor.clone();
    child_anchor.name = owner;
    Resolver::new(
        transport,
        ResolverConfig {
            trust_anchors: vec![anchor, child_anchor],
            root_servers: vec![(std::net::Ipv4Addr::LOCALHOST, 53).into()],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    )
}

#[tokio::test]
async fn signed_parent_ds_at_direct_child_anchor_is_secure() {
    let (transport, anchor, mut question) = fixtures::delegated_fixture();
    question.qname = name(&["child", "example"]);
    question.qtype = QueryType::DS;
    let resolver = with_child_anchor(transport, anchor, question.qname.clone());
    let mut result = resolver.resolve(question.clone()).await.unwrap();
    assert!(result.headers.ad);
    assert_eq!(
        resolver
            .validate_dnssec_response(&question, &mut result)
            .await
            .unwrap(),
        dns::DnssecSecurityStatus::Secure
    );
}

#[tokio::test]
async fn ordinary_parent_signed_data_cannot_bypass_child_anchor() {
    let owner = name(&["child", "example"]);
    let (transport, anchor, question) = fixtures::signed_record_fixture(
        false,
        owner.clone(),
        QueryType::A,
        RecordType::A,
        RData::A(std::net::Ipv4Addr::LOCALHOST),
    );
    let resolver = with_child_anchor(transport, anchor, owner);
    assert!(matches!(
        resolver.resolve(question).await,
        Err(ResolveError::DnssecBogus(_))
    ));
}

#[tokio::test]
async fn parent_denial_at_direct_child_anchor_is_secure() {
    let (transport, anchor, mut question) = negative::negative_ds_fixture();
    question.qtype = QueryType::DS;
    let resolver = with_child_anchor(transport, anchor, question.qname.clone());
    let mut result = resolver.resolve(question.clone()).await.unwrap();
    assert!(result.headers.ad);
    assert_eq!(
        resolver
            .validate_dnssec_response(&question, &mut result)
            .await
            .unwrap(),
        dns::DnssecSecurityStatus::Secure
    );
}

#[test]
fn ds_still_respects_strict_ancestor_anchors_and_signer_namespace() {
    let (transport, anchor, _) = fixtures::signed_fixture(false);
    let child = name(&["child", "example"]);
    let resolver = with_child_anchor(transport, anchor, child.clone());
    assert!(
        resolver
            .check_answer_zone(
                &name(&["sub", "child", "example"]),
                &name(&["example"]),
                ClassType::IN,
                true
            )
            .is_err()
    );
    assert!(
        resolver
            .check_answer_zone(&child, &name(&["unrelated"]), ClassType::IN, true)
            .is_err()
    );
    assert!(
        resolver
            .check_answer_zone(&child, &child, ClassType::IN, true)
            .is_err()
    );
}

/// A child authority legitimately returns apex NODATA for DS, but that
/// response says nothing about the parent's signed delegation data.
#[derive(Clone)]
struct NamespaceTransport {
    inner: super::support::DelegatedTransport,
    parent_address: std::net::SocketAddr,
    ds_servers: std::sync::Arc<std::sync::Mutex<Vec<std::net::SocketAddr>>>,
}

impl transport::Transport for NamespaceTransport {
    fn exchange<'future>(
        &'future self,
        server: std::net::SocketAddr,
        query: &'future dns::Message,
        timeout: std::time::Duration,
    ) -> transport::BoxFuture<'future, Result<dns::Message, transport::TransportError>> {
        Box::pin(async move {
            if query.questions[0].qtype == QueryType::DS {
                self.ds_servers.lock().unwrap().push(server);
                if server != self.parent_address {
                    let mut child_nodata = self.inner.ds.clone();
                    child_nodata.answers.clear();
                    child_nodata.headers.id = query.headers.id;
                    child_nodata.questions.clone_from(&query.questions);
                    return Ok(child_nodata);
                }
            }
            self.inner.exchange(server, query, timeout).await
        })
    }
}

#[tokio::test]
async fn cached_child_delegation_does_not_redirect_chain_ds_queries_to_child() {
    let (inner, anchor, question) = fixtures::delegated_fixture();
    let parent_address = "192.0.2.1:53".parse().unwrap();
    let child_address = "192.0.2.2:53".parse().unwrap();
    let ds_servers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let resolver = fixtures::resolver(
        NamespaceTransport {
            inner,
            parent_address,
            ds_servers: std::sync::Arc::clone(&ds_servers),
        },
        anchor,
    );
    for (zone, address) in [
        (name(&["example"]), parent_address),
        (name(&["child", "example"]), child_address),
    ] {
        resolver.delegation_cache.insert(
            &crate::protocol::Referral {
                name_servers: vec![zone.clone()],
                zone,
                class: ClassType::IN,
                candidates: vec![address],
                candidate_ttls: vec![(address, std::time::Duration::from_secs(60))],
                trusted_glue: Vec::new(),
                ttl: std::time::Duration::from_secs(60),
            },
            std::time::Duration::from_secs(60),
        );
    }
    assert!(resolver.resolve(question).await.unwrap().headers.ad);
    assert_eq!(*ds_servers.lock().unwrap(), [parent_address]);
}

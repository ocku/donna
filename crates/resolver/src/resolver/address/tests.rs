use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use dns::{ClassType, DomainName, Headers, Message, QueryType, RData, RecordType, ResourceRecord};
use transport::{Transport, TransportError, TransportProtocol};

use super::{
    NAME_SERVER_FAMILY_STAGGER, NameServerAddressFamilies, NameServerAddressResolution,
    PendingNameServer,
};
use crate::{ResolverConfig, resolver::AlgorithmSignals, stats::StatsContext};

fn name(label: &str) -> DomainName {
    DomainName::from_labels(vec![label.as_bytes().to_vec(), b"example".to_vec()]).unwrap()
}

#[derive(Clone)]
struct FamilyTransport {
    calls: Arc<Mutex<Vec<QueryType>>>,
    a_delay: Option<Duration>,
    a_completed: Arc<AtomicBool>,
}

impl Transport for FamilyTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let question = &query.questions[0];
            self.calls.lock().unwrap().push(question.qtype);
            if question.qtype == QueryType::A {
                if let Some(delay) = self.a_delay {
                    tokio::time::sleep(delay).await;
                }
                self.a_completed.store(true, Ordering::Relaxed);
            }
            let (rtype, rdata) = match question.qtype {
                QueryType::A => (RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 53))),
                QueryType::AAAA => (RecordType::AAAA, RData::AAAA(Ipv6Addr::LOCALHOST)),
                _ => unreachable!("family lookup only asks for A or AAAA"),
            };
            Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: vec![ResourceRecord {
                    name: question.qname.clone(),
                    rtype,
                    class: ClassType::IN,
                    ttl: 60,
                    rdata,
                }],
                authorities: Vec::new(),
                additionals: Vec::new(),
            })
        })
    }
}

fn family_resolver(
    a_delay: Option<Duration>,
) -> (
    super::Resolver<FamilyTransport>,
    Arc<Mutex<Vec<QueryType>>>,
    Arc<AtomicBool>,
) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let a_completed = Arc::new(AtomicBool::new(false));
    let resolver = super::Resolver::new(
        FamilyTransport {
            calls: Arc::clone(&calls),
            a_delay,
            a_completed: Arc::clone(&a_completed),
        },
        ResolverConfig {
            root_servers: vec!["192.0.2.1:53".parse().unwrap()],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    (resolver, calls, a_completed)
}

#[tokio::test(start_paused = true)]
async fn fast_a_defers_aaaa_without_transmitting_it() {
    let (resolver, calls, _) = family_resolver(None);
    let name_server = name("ns");

    let resolution = resolver
        .resolve_name_server_addresses(
            std::slice::from_ref(&name_server),
            &[],
            Arc::new(AtomicUsize::new(4)),
            None,
            Arc::new(AlgorithmSignals::default()),
        )
        .await;

    assert_eq!(*calls.lock().unwrap(), [QueryType::A]);
    assert_eq!(resolution.addresses, ["192.0.2.53:53".parse().unwrap()]);
    assert_eq!(resolution.pending_name_servers.len(), 1);
    assert_eq!(resolution.pending_name_servers[0].name, name_server);
    assert_eq!(
        resolution.pending_name_servers[0].families,
        NameServerAddressFamilies::Aaaa
    );
    assert!(!resolution.pending_name_servers[0].is_suspended());
}

#[tokio::test(start_paused = true)]
async fn slow_a_is_overtaken_without_detached_work_and_shares_the_budget() {
    let (resolver, calls, a_completed) = family_resolver(Some(NAME_SERVER_FAMILY_STAGGER * 2));
    let remaining_steps = Arc::new(AtomicUsize::new(2));
    let stats = Arc::new(StatsContext::new(1));
    let name_server = name("ns");

    let resolution = resolver
        .resolve_name_server_addresses(
            std::slice::from_ref(&name_server),
            &[],
            Arc::clone(&remaining_steps),
            Some(Arc::clone(&stats)),
            Arc::new(AlgorithmSignals::default()),
        )
        .await;

    assert_eq!(*calls.lock().unwrap(), [QueryType::A, QueryType::AAAA]);
    assert_eq!(remaining_steps.load(Ordering::Relaxed), 0);
    assert_eq!(resolution.addresses, ["[::1]:53".parse().unwrap()]);
    assert_eq!(resolution.pending_name_servers.len(), 1);
    assert_eq!(resolution.pending_name_servers[0].name, name_server);
    assert_eq!(
        resolution.pending_name_servers[0].families,
        NameServerAddressFamilies::A
    );
    assert!(resolution.pending_name_servers[0].is_suspended());
    assert!(!a_completed.load(Ordering::Relaxed));
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!a_completed.load(Ordering::Relaxed));

    let snapshot = stats.snapshot(None);
    assert_eq!(snapshot.udp_transmissions(), 2);
    assert_eq!(snapshot.name_server_family_races(), 1);
    assert_eq!(snapshot.canceled_name_server_family_lookups(), 0);
    assert_eq!(snapshot.timeouts(), 0);
    drop(resolution);
    assert_eq!(
        stats.snapshot(None).canceled_name_server_family_lookups(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn deferred_a_after_aaaa_winner_precedes_later_name_servers() {
    let (resolver, calls, a_completed) = family_resolver(Some(NAME_SERVER_FAMILY_STAGGER * 2));
    let remaining_steps = Arc::new(AtomicUsize::new(4));
    let first_name_server = name("ns1");
    let later_name_server = name("ns2");
    let initial = vec![
        PendingNameServer::both(first_name_server.clone()),
        PendingNameServer::both(later_name_server.clone()),
    ];

    let first = resolver
        .resolve_pending_name_server_addresses(
            initial,
            &[],
            Arc::clone(&remaining_steps),
            None,
            Arc::new(AlgorithmSignals::default()),
        )
        .await;
    assert_eq!(first.addresses, ["[::1]:53".parse().unwrap()]);
    assert_eq!(first.pending_name_servers[0].name, first_name_server);
    assert_eq!(
        first.pending_name_servers[0].families,
        NameServerAddressFamilies::A
    );
    assert_eq!(first.pending_name_servers[1].name, later_name_server);

    assert!(first.pending_name_servers[0].is_suspended());
    let fallback = resolver
        .resolve_pending_name_server_addresses(
            first.pending_name_servers,
            &[],
            Arc::clone(&remaining_steps),
            None,
            Arc::new(AlgorithmSignals::default()),
        )
        .await;

    assert_eq!(fallback.addresses, ["192.0.2.53:53".parse().unwrap()]);
    assert_eq!(*calls.lock().unwrap(), [QueryType::A, QueryType::AAAA]);
    assert!(a_completed.load(Ordering::Relaxed));
    assert_eq!(remaining_steps.load(Ordering::Relaxed), 2);
    assert_eq!(fallback.pending_name_servers.len(), 1);
    assert_eq!(fallback.pending_name_servers[0].name, later_name_server);
}

#[test]
fn pending_name_servers_exclude_dependency_cycles_but_keep_later_hosts() {
    let cyclic = name("cyclic");
    let safe = name("safe");

    let resolution = NameServerAddressResolution::complete(
        vec!["192.0.2.1:53".parse().unwrap()],
        [
            PendingNameServer::both(cyclic.clone()),
            PendingNameServer::both(safe.clone()),
        ],
        &[cyclic],
    );

    assert_eq!(resolution.pending_name_servers.len(), 1);
    assert_eq!(resolution.pending_name_servers[0].name, safe);
    assert_eq!(
        resolution.pending_name_servers[0].families,
        NameServerAddressFamilies::Both
    );
}

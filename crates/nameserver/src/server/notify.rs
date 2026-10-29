use std::{fmt, net::SocketAddr, num::NonZeroU8, sync::Arc, time::Duration};

use dns::{
    ClassType, Headers, Message, OpCode, QClassType, QueryType, Question, RCode, RecordType,
};
use tracing::{debug, warn};
use transport::{Transport, TransportProtocol};

use crate::Zone;

use super::NameServer;

/// One operator-selected server in a zone's RFC 1996 notify set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NotifyTarget {
    /// Zone apex whose changes are sent to this target.
    pub zone: dns::DomainName,
    /// Zone class selected at an apex that hosts multiple classes.
    pub class: ClassType,
    /// DNS server address and port that receives NOTIFY transactions.
    pub server: SocketAddr,
}

impl NotifyTarget {
    /// Creates one explicit notify-set member.
    #[must_use]
    pub const fn new(zone: dns::DomainName, class: ClassType, server: SocketAddr) -> Self {
        Self {
            zone,
            class,
            server,
        }
    }
}

/// Configures outbound RFC 1996 NOTIFY transactions.
#[derive(Clone)]
pub struct NotifyConfig {
    pub(super) transport: Arc<dyn Transport>,
    pub(super) targets: Vec<NotifyTarget>,
    pub(super) retry_interval: Duration,
    pub(super) max_attempts: NonZeroU8,
}

impl NotifyConfig {
    /// RFC 1996's suggested retry interval and per-attempt timeout.
    pub const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_secs(60);
    /// RFC 1996's suggested maximum number of UDP transmissions.
    pub const DEFAULT_MAX_ATTEMPTS: NonZeroU8 = NonZeroU8::new(5).unwrap();

    /// Creates a notify policy with the RFC-suggested retry defaults.
    pub fn new<T>(transport: T, targets: impl IntoIterator<Item = NotifyTarget>) -> Self
    where
        T: Transport + 'static,
    {
        Self {
            transport: Arc::new(transport),
            targets: targets.into_iter().collect(),
            retry_interval: Self::DEFAULT_RETRY_INTERVAL,
            max_attempts: Self::DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Replaces the interval/timeout and bounded transmission count.
    #[must_use]
    pub const fn with_retry_policy(
        mut self,
        retry_interval: Duration,
        max_attempts: NonZeroU8,
    ) -> Self {
        self.retry_interval = retry_interval;
        self.max_attempts = max_attempts;
        self
    }

    /// Returns the configured operator-selected notify set.
    #[must_use]
    pub fn targets(&self) -> &[NotifyTarget] {
        &self.targets
    }
}

impl fmt::Debug for NotifyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotifyConfig")
            .field("transport", &"<dyn Transport>")
            .field("targets", &self.targets)
            .field("retry_interval", &self.retry_interval)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl NameServer {
    pub(super) async fn notify_zone_change(&self, zone: &Zone) {
        let Some(config) = &self.config.notify else {
            return;
        };
        let Some(soa) = zone
            .records()
            .iter()
            .find(|record| record.name.eq_dns(zone.apex()) && record.rtype == RecordType::SOA)
            .cloned()
        else {
            return;
        };

        let mut scheduled = Vec::new();
        for target in config
            .targets
            .iter()
            .filter(|target| target.zone.eq_dns(zone.apex()) && target.class == zone.class())
        {
            if scheduled.contains(&target.server) {
                continue;
            }
            scheduled.push(target.server);
            let request = Message::builder()
                .headers(Headers {
                    id: self.next_notify_id(),
                    opcode: OpCode::Notify,
                    aa: true,
                    ..Headers::default()
                })
                .questions([Question {
                    qname: zone.apex().clone(),
                    qtype: QueryType::SOA,
                    qclass: QClassType::Class(zone.class()),
                }])
                .answers([soa.clone()])
                .build()
                .expect("a validated zone produces a valid NOTIFY hint");
            let transport = Arc::clone(&config.transport);
            let interval = config.retry_interval;
            let attempts = config.max_attempts;
            let server = target.server;
            let task_key = (
                crate::name::dns_name_key(zone.apex()),
                zone.class().value(),
                server,
            );
            let mut tasks = self.notify_tasks.lock().await;
            if let Some(pending) = tasks.get_mut(&task_key) {
                *pending = Some(request);
                continue;
            }
            tasks.insert(task_key.clone(), None);
            drop(tasks);
            let tasks = Arc::clone(&self.notify_tasks);
            tokio::spawn(async move {
                send_coalesced(
                    transport, server, request, interval, attempts, tasks, task_key,
                )
                .await;
            });
        }
    }

    fn next_notify_id(&self) -> u16 {
        self.notify_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

async fn send_coalesced(
    transport: Arc<dyn Transport>,
    server: SocketAddr,
    mut request: Message,
    interval: Duration,
    max_attempts: NonZeroU8,
    tasks: Arc<tokio::sync::Mutex<super::NotifyTasks>>,
    task_key: super::NotifyTaskKey,
) {
    loop {
        send_with_retries(
            Arc::clone(&transport),
            server,
            request,
            interval,
            max_attempts,
        )
        .await;
        let mut active = tasks.lock().await;
        let next = active.get_mut(&task_key).and_then(Option::take);
        if next.is_none() {
            active.remove(&task_key);
        }
        drop(active);
        let Some(next) = next else {
            return;
        };
        request = next;
    }
}

async fn send_with_retries(
    transport: Arc<dyn Transport>,
    server: SocketAddr,
    request: Message,
    interval: Duration,
    max_attempts: NonZeroU8,
) {
    let attempts = if matches!(
        transport.protocol(),
        Some(TransportProtocol::Tcp | TransportProtocol::Tls)
    ) {
        1
    } else {
        max_attempts.get()
    };
    for attempt in 1..=attempts {
        let next_attempt = tokio::time::Instant::now().checked_add(interval);
        match transport.exchange(server, &request, interval).await {
            Ok(response)
                if response.headers.rcode == RCode::NotImplemented
                    || response.validate_for_forwarding().is_ok() =>
            {
                debug!(%server, attempt, "NOTIFY transaction acknowledged");
                return;
            }
            Ok(_) => debug!(%server, attempt, "ignoring malformed NOTIFY response"),
            Err(error) => debug!(%server, attempt, %error, "NOTIFY attempt failed"),
        }
        if attempt < attempts
            && let Some(next_attempt) = next_attempt
        {
            tokio::time::sleep_until(next_attempt).await;
        }
    }
    warn!(%server, attempts, "NOTIFY transaction timed out");
}

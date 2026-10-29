//! Per-question, address and wire-protocol transmission accounting (RFC 9520).
use crate::protocol::MAX_TRANSMISSIONS_PER_SERVER;
use dns::Question;
use std::net::SocketAddr;
use transport::TransportProtocol;

#[derive(Default)]
pub(super) struct RetryBudget {
    entries: Vec<Entry>,
}
struct Entry {
    name: Box<[u8]>,
    qtype: u16,
    qclass: u16,
    server: SocketAddr,
    protocol: Option<TransportProtocol>,
    count: u8,
}
impl Entry {
    fn matches(
        &self,
        q: &Question,
        name: &[u8],
        server: SocketAddr,
        protocol: Option<TransportProtocol>,
    ) -> bool {
        self.server == server
            && self.protocol == protocol
            && self.qtype == q.qtype.value()
            && self.qclass == q.qclass.value()
            && self.name.as_ref() == name
    }
}
impl RetryBudget {
    // Only a semantically accepted strict-descendant referral is useful progress.
    // It restores this respondent, never failed peers or other transports.
    pub(super) fn progressed(
        &mut self,
        q: &Question,
        server: SocketAddr,
        protocol: Option<TransportProtocol>,
    ) {
        let name = crate::name::packed_key(&q.qname);
        self.entries
            .retain(|e| !e.matches(q, &name, server, protocol));
    }

    pub(super) fn reserve(
        &mut self,
        q: &Question,
        server: SocketAddr,
        protocol: Option<TransportProtocol>,
        configured_udp_attempts: u8,
    ) -> bool {
        let name = crate::name::packed_key(&q.qname);
        let limit = if protocol == Some(TransportProtocol::Udp) {
            configured_udp_attempts.clamp(1, MAX_TRANSMISSIONS_PER_SERVER)
        } else {
            MAX_TRANSMISSIONS_PER_SERVER
        };
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.matches(q, &name, server, protocol))
        {
            if entry.count >= limit {
                return false;
            }
            entry.count += 1;
        } else {
            self.entries.push(Entry {
                name,
                qtype: q.qtype.value(),
                qclass: q.qclass.value(),
                server,
                protocol,
                count: 1,
            });
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{ClassType, DomainName, QClassType, QueryType};
    fn q() -> Question {
        Question {
            qname: DomainName::from_dotted("retry.example.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }
    }
    #[test]
    fn identities_and_protocols_have_independent_budgets() {
        let mut budget = RetryBudget::default();
        let server = "192.0.2.1:53".parse().unwrap();
        let mut question = q();
        for _ in 0..3 {
            assert!(budget.reserve(&question, server, Some(TransportProtocol::Udp), 255));
        }
        assert!(!budget.reserve(&question, server, Some(TransportProtocol::Udp), 255));
        for _ in 0..3 {
            assert!(budget.reserve(&question, server, Some(TransportProtocol::Tcp), 1));
        }
        assert!(!budget.reserve(&question, server, Some(TransportProtocol::Tcp), 1));
        question.qname = DomainName::from_dotted("RETRY.EXAMPLE.").unwrap();
        assert!(!budget.reserve(&question, server, Some(TransportProtocol::Udp), 255));
        question.qtype = QueryType::AAAA;
        assert!(budget.reserve(&question, server, Some(TransportProtocol::Udp), 1));
        assert!(!budget.reserve(&question, server, Some(TransportProtocol::Udp), 1));
        question.qclass = QClassType::Class(ClassType::CH);
        assert!(budget.reserve(&question, server, Some(TransportProtocol::Udp), 1));
        assert!(budget.reserve(
            &q(),
            "192.0.2.2:53".parse().unwrap(),
            Some(TransportProtocol::Udp),
            1
        ));
        question.qname = DomainName::from_dotted("other.example.").unwrap();
        assert!(budget.reserve(&question, server, Some(TransportProtocol::Udp), 0));
        assert!(!budget.reserve(&question, server, Some(TransportProtocol::Udp), 0));
    }
    #[test]
    fn useful_progress_only_restores_the_responding_tuple() {
        let mut budget = RetryBudget::default();
        let server = "192.0.2.1:53".parse().unwrap();
        let peer = "192.0.2.2:53".parse().unwrap();
        for endpoint in [server, peer] {
            for protocol in [TransportProtocol::Udp, TransportProtocol::Tcp] {
                for _ in 0..3 {
                    assert!(budget.reserve(&q(), endpoint, Some(protocol), 3));
                }
            }
        }
        budget.progressed(&q(), server, Some(TransportProtocol::Udp));
        assert!(budget.reserve(&q(), server, Some(TransportProtocol::Udp), 3));
        assert!(!budget.reserve(&q(), peer, Some(TransportProtocol::Udp), 3));
        assert!(!budget.reserve(&q(), server, Some(TransportProtocol::Tcp), 3));
    }
}

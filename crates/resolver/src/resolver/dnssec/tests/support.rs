use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use dns::{DomainName, Message, QueryType};
use rsa::rand_core::{CryptoRng, Error as RandomError, RngCore};
use transport::{Transport, TransportError};

pub(super) struct TestRng(pub(super) u64);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

#[derive(Clone)]
pub(super) struct SignedTransport {
    pub(super) answer: Message,
    pub(super) dnskey: Message,
    pub(super) requests: Arc<Mutex<Vec<Message>>>,
}

#[derive(Clone)]
pub(super) struct InsecureTransport {
    pub(super) answer: Message,
    pub(super) soa: Message,
    pub(super) ds: Message,
    pub(super) dnskey: Message,
    pub(super) requests: Arc<Mutex<Vec<Message>>>,
}

#[derive(Clone)]
pub(super) struct DelegatedTransport {
    pub(super) parent: DomainName,
    pub(super) answer: Message,
    pub(super) ds: Message,
    pub(super) parent_dnskey: Message,
    pub(super) child_dnskey: Message,
    pub(super) requests: Arc<Mutex<Vec<Message>>>,
}

impl Transport for SignedTransport {
    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(query.clone());
            let mut response = match query.questions[0].qtype {
                QueryType::DNSKEY => self.dnskey.clone(),
                _ => self.answer.clone(),
            };
            response.headers.id = query.headers.id;
            response.questions.clone_from(&query.questions);
            Ok(response)
        })
    }
}

impl Transport for InsecureTransport {
    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(query.clone());
            let mut response = match query.questions[0].qtype {
                QueryType::A => self.answer.clone(),
                QueryType::SOA => self.soa.clone(),
                QueryType::DS => self.ds.clone(),
                QueryType::DNSKEY => self.dnskey.clone(),
                other => panic!("unexpected validation query {other:?}"),
            };
            response.headers.id = query.headers.id;
            response.questions.clone_from(&query.questions);
            Ok(response)
        })
    }
}

impl Transport for DelegatedTransport {
    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(query.clone());
            let question = &query.questions[0];
            let mut response = match question.qtype {
                QueryType::A => self.answer.clone(),
                QueryType::DS => self.ds.clone(),
                QueryType::DNSKEY if question.qname.eq_dns(&self.parent) => {
                    self.parent_dnskey.clone()
                }
                QueryType::DNSKEY => self.child_dnskey.clone(),
                other => panic!("unexpected validation query {other:?}"),
            };
            response.headers.id = query.headers.id;
            response.questions.clone_from(&query.questions);
            Ok(response)
        })
    }
}

pub(super) fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

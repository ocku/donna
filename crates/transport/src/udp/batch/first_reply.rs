use super::*;
use crate::{DnsRequest, ImmediateUdpResponse};
use dns::{DomainName, Headers, IntoWire, Message, QClassType, QueryType, Question};
use std::{
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Default)]
struct Gate {
    released: Mutex<bool>,
    condition: Condvar,
    timed_out: AtomicBool,
}

struct PauseSecond(Arc<Gate>);

impl DnsRequestHandler for PauseSecond {
    fn try_handle_udp(
        &self,
        query: &Message,
        _: &[u8],
        _: SocketAddr,
        _: usize,
    ) -> Option<ImmediateUdpResponse> {
        if query.headers.id == 2 {
            let released = self.0.released.lock().unwrap();
            let (_released, result) = self
                .0
                .condition
                .wait_timeout_while(released, Duration::from_secs(1), |released| !*released)
                .unwrap();
            self.0.timed_out.store(result.timed_out(), Ordering::SeqCst);
        }
        Some(ImmediateUdpResponse::Message(
            Message::builder()
                .headers(Headers {
                    id: query.headers.id,
                    qr: true,
                    ..Headers::default()
                })
                .questions(query.questions.clone())
                .build()
                .unwrap(),
        ))
    }

    fn handle<'a>(&'a self, _: DnsRequest) -> crate::BoxFuture<'a, ()> {
        Box::pin(async { panic!("both packets have immediate replies") })
    }
}

fn query(id: u16) -> Vec<u8> {
    Message::builder()
        .headers(Headers {
            id,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted("example.test.").unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(dns::ClassType::IN),
        }])
        .build()
        .unwrap()
        .into_wire()
        .unwrap()
}

// No public contract requires a synchronous immediate handler to avoid waiting.
// A later slot must not hold an already prepared reply until its send deadline.
#[tokio::test]
async fn first_reply_is_sent_before_a_later_immediate_handler_returns() {
    use dns::FromWire;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    // Queue both packets before starting the receive loop, making one batch.
    for id in [1, 2] {
        client.send_to(&query(id), address).unwrap();
    }
    let gate = Arc::new(Gate::default());
    let permits = Arc::new(Semaphore::new(2));
    let server = tokio::spawn(receive_packets(
        socket,
        Arc::new(PauseSecond(gate.clone())),
        UdpServerPolicy {
            packet_limit: 2,
            handler_reply_timeout: Duration::from_secs(2),
            response_send_timeout: Duration::from_millis(50),
        },
        None,
        permits.clone(),
        2,
    ));
    // The independent OS thread can receive while the Tokio worker is blocked
    // in the second synchronous handler. It releases that handler only after
    // receiving the first packet, or after a bounded diagnostic timeout.
    let release = gate.clone();
    let (first, second) = tokio::task::spawn_blocking(move || {
        let mut buffer = [0; 512];
        let first = client.recv_from(&mut buffer).ok().map(|(n, peer)| {
            assert_eq!(peer, address);
            Message::from_wire(&buffer[..n]).unwrap().headers.id
        });
        *release.released.lock().unwrap() = true;
        release.condition.notify_all();
        let second = client
            .recv_from(&mut buffer)
            .ok()
            .map(|(n, _)| Message::from_wire(&buffer[..n]).unwrap().headers.id);
        (first, second)
    })
    .await
    .unwrap();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert_eq!(first, Some(1), "a later handler delayed the first reply");
    assert_eq!(second, Some(2));
    assert!(!gate.timed_out.load(Ordering::SeqCst));
    assert_eq!(permits.available_permits(), 2);
}

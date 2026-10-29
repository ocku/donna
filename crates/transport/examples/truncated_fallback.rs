//! Classic UDP to TCP fallback against the interop lab's 96-address RRset.
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use dns::{ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData};
use transport::{TransitionReason, Transport, UdpTransport};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address: SocketAddr = std::env::args()
        .nth(1)
        .ok_or("expected DNS server address")?
        .parse()?;
    let request = Message::builder()
        .headers(Headers {
            id: 0x2000,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted("many.example.test.")?,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()?;
    let udp = UdpTransport;
    let truncated = match udp
        .exchange(address, &request, Duration::from_secs(2))
        .await
    {
        Ok(reply) => reply,
        Err(error) => {
            println!("{{\"udp_error\":\"{error}\",\"tcp_completed\":false}}");
            return Err(error.into());
        }
    };
    assert!(truncated.headers.tc);
    assert!(truncated.answers.is_empty());
    let complete = udp
        .transition(TransitionReason::TruncatedResponse)
        .ok_or("TCP transition unavailable")?
        .exchange(address, &request, Duration::from_secs(2))
        .await?;
    assert!(!complete.headers.tc);
    assert_eq!(complete.answers.len(), 96);
    for last in 1..=96 {
        assert!(complete.answers.iter().any(|rr| {
            rr.name.eq_dns(&request.questions[0].qname)
                && rr.rdata == RData::A(Ipv4Addr::new(192, 0, 2, last))
        }));
    }
    println!("{{\"udp_tc\":true,\"udp_answers\":0,\"tcp_completed\":true,\"tcp_answers\":96}}");
    Ok(())
}

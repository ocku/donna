//! Query a chosen nameserver with the public transport API.
use dns::{ClassType, DomainName, Message, QClassType, QueryType, Question};
use std::{env, net::SocketAddr, time::Duration};
use transport::{TcpTransport, Transport, UdpTransport};
type Failure = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let args: Vec<_> = env::args().collect();
    let protocol = args.get(1).map(String::as_str).unwrap_or("udp");
    let address: SocketAddr = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("127.0.0.1:5300")
        .parse()?;
    let name = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("www.example.test.");
    let transport: Box<dyn Transport> = match protocol {
        "udp" => Box::new(UdpTransport),
        "tcp" => Box::new(TcpTransport),
        _ => return Err("expected udp or tcp".into()),
    };
    let query = Message::builder()
        .questions([Question {
            qname: DomainName::from_dotted(name)?,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()?;
    let answer = transport
        .exchange(address, &query, Duration::from_secs(5))
        .await?;
    println!("{:?}", answer);
    Ok(())
}

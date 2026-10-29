//! Embed Donna's iterative resolver against the laboratory's BIND hierarchy.

use std::{env, net::SocketAddr, time::Duration};

use dns::{ClassType, DomainName, QClassType, QueryType, Question, RCode, RData};
use resolver::{ResolutionCacheSource, Resolver, ResolverConfig};
use transport::UdpTransport;

type Failure = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let root: SocketAddr = env::var("ROOT_SERVER")
        .unwrap_or_else(|_| "172.29.53.22:53".into())
        .parse()?;
    // The isolated hierarchy is unsigned. Production applications should
    // configure and maintain their own trust anchors when validating DNSSEC.
    let resolver = Resolver::new(
        UdpTransport,
        ResolverConfig {
            root_servers: vec![root],
            timeout: Duration::from_secs(2),
            ..ResolverConfig::default()
        },
    );
    let question = Question {
        qname: DomainName::from_dotted("www.example.test.")?,
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    let cold = resolver.resolve_with_stats(question.clone()).await?;
    assert_eq!(cold.response().headers.rcode, RCode::Ok);
    assert!(cold.response().answers.iter().any(|record| matches!(
        record.rdata, RData::A(address) if address.octets() == [192, 0, 2, 80]
    )));
    assert!(cold.stats().referrals_followed() >= 2);
    let warm = resolver.resolve_with_stats(question).await?;
    assert_eq!(warm.response().headers.rcode, RCode::Ok);
    assert!(warm.response().answers.iter().any(|record| matches!(
        record.rdata, RData::A(address) if address.octets() == [192, 0, 2, 80]
    )));
    assert_eq!(
        warm.stats().final_cache_source(),
        Some(ResolutionCacheSource::Positive)
    );
    assert_eq!(warm.stats().udp_transmissions(), 0);
    println!(
        "PASS embedded resolver: {} referrals, repeated answer from positive cache",
        cold.stats().referrals_followed()
    );
    Ok(())
}

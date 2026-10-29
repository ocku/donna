use super::{cli::*, config::ResolverSettings, net, output};
use anyhow::{Context, Result, bail};
use dns::{DomainName, Edns, Headers, Message, QueryType, Question};
use resolver::Resolver;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use transport::UdpTransport;

pub fn reverse(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!(
            "{}.in-addr.arpa.",
            ip.octets()
                .iter()
                .rev()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(".")
        ),
        IpAddr::V6(ip) => format!(
            "{}.ip6.arpa.",
            format!("{:032x}", u128::from(ip))
                .chars()
                .rev()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(".")
        ),
    }
}

async fn questions(args: &QuestionArgs) -> Result<Vec<Question>> {
    let names = if let Some(ip) = args.reverse {
        vec![reverse(ip)]
    } else if let Some(path) = &args.batch {
        let content = if path.as_os_str() == "-" {
            use tokio::io::AsyncReadExt;
            let mut content = String::new();
            tokio::io::stdin().read_to_string(&mut content).await?;
            content
        } else {
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
        };
        content
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    } else {
        vec![
            args.name
                .clone()
                .context("supply a domain, --reverse IP, or --batch FILE")?,
        ]
    };
    if names.is_empty() {
        bail!("batch contains no domains");
    }
    let types = if args.reverse.is_some() {
        vec![QueryType::PTR]
    } else {
        args.types.clone()
    };
    let class = args.class;
    let mut questions = Vec::new();
    for name in names {
        for qtype in &types {
            questions.push(Question {
                qname: DomainName::from_dotted(&name)?,
                qtype: *qtype,
                qclass: class,
            });
        }
    }
    Ok(questions)
}

pub fn query(question: Question) -> Result<Message> {
    let mut id = [0; 2];
    getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("transaction ID entropy: {e}"))?;
    Ok(Message {
        headers: Headers {
            id: u16::from_ne_bytes(id),
            rd: true,
            ad: true,
            ..Headers::default()
        },
        questions: vec![question],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    })
}

pub async fn run_query(args: QueryArgs) -> Result<()> {
    let port = args.port.unwrap_or(args.endpoint.protocol.port());
    let transport = net::client(&args.endpoint, port)?;
    let servers = if args.server.is_empty() {
        net::system_servers()?
    } else {
        args.server.clone()
    };
    let mut addresses = Vec::new();
    for server in servers {
        let mut address = net::address(&server, port).await?;
        if args.port.is_some() {
            address.set_port(port);
        }
        addresses.push(address);
    }
    let mut failures = 0;
    for question in questions(&args.question).await? {
        let mut request = query(question)?;
        request.headers.rd = !args.no_recurse;
        request.headers.cd = args.checking_disabled;
        if !args.no_edns {
            request.additionals.push(
                Edns {
                    dnssec_ok: args.dnssec && !args.no_dnssec,
                    udp_payload_size: args.udp_size,
                    ..Edns::default()
                }
                .into_record(),
            );
        }
        if request.questions[0].qtype == QueryType::IXFR {
            bail!("IXFR requires transfer history and a serial; use AXFR with this client");
        }
        let operation = query_servers(&transport, &addresses, &request, &args);
        match tokio::time::timeout(Duration::from_secs(args.question.deadline), operation).await {
            Ok(result) => failures += result?,
            Err(_) => {
                failures += 1;
                eprintln!("question exceeded {}s deadline", args.question.deadline);
            }
        }
    }
    if failures > 0 {
        bail!("{failures} query operation(s) failed");
    }
    Ok(())
}

async fn query_servers(
    client: &net::Client,
    addresses: &[std::net::SocketAddr],
    request: &Message,
    args: &QueryArgs,
) -> Result<usize> {
    let mut failures = 0;
    let mut last_rejection = None;
    for address in addresses {
        let mut response = None;
        for _ in 0..args.attempts {
            let started = Instant::now();
            match client
                .exchange(*address, request, Duration::from_secs(args.timeout))
                .await
            {
                Ok(answer) => {
                    response = Some((answer, started.elapsed()));
                    break;
                }
                Err(error) => eprintln!("{address}: {error}"),
            }
        }
        let Some((answer, elapsed)) = response else {
            if args.compare {
                failures += 1;
            }
            continue;
        };
        let rejected = [dns::RCode::ServerFailure, dns::RCode::Refused]
            .into_iter()
            .any(|code| answer.extended_rcode() == u16::from(u8::from(code)));
        if rejected && !args.compare {
            last_rejection = Some((answer, *address, elapsed));
            continue;
        }
        output::print(
            &answer,
            &address.to_string(),
            elapsed,
            args.question.output_format(),
        )?;
        if !args.compare {
            return Ok(0);
        }
        failures += usize::from(rejected);
    }
    if !args.compare {
        if let Some((answer, address, elapsed)) = last_rejection {
            output::print(
                &answer,
                &address.to_string(),
                elapsed,
                args.question.output_format(),
            )?;
        }
        return Ok(1);
    }
    Ok(failures)
}

pub async fn run_resolve(args: ResolveArgs) -> Result<()> {
    let settings = ResolverSettings {
        root_servers: args.root,
        validate: !args.no_validate,
        trust_anchors: args.trust_anchors,
        ..ResolverSettings::default()
    };
    let resolver = Resolver::new(
        TraceTransport {
            enabled: args.trace,
        },
        settings.build(std::path::Path::new("."))?,
    );
    let mut failures = 0;
    for question in questions(&args.question).await? {
        let result = tokio::time::timeout(
            Duration::from_secs(args.question.deadline),
            resolver.resolve_with_stats(question),
        )
        .await;
        match result {
            Ok(Ok(result)) => {
                let (message, stats) = result.into_parts();
                output::print(
                    &message,
                    "iterative",
                    stats.elapsed(),
                    args.question.output_format(),
                )?;
                if args.stats {
                    eprintln!("{stats:#?}");
                }
            }
            Ok(Err(error)) => {
                failures += 1;
                eprintln!("{error}");
            }
            Err(_) => {
                failures += 1;
                eprintln!("resolution deadline exceeded");
            }
        }
    }
    if failures > 0 {
        bail!("{failures} resolution(s) failed");
    }
    Ok(())
}

struct TraceTransport {
    enabled: bool,
}

impl transport::Transport for TraceTransport {
    fn protocol(&self) -> Option<transport::TransportProtocol> {
        UdpTransport.protocol()
    }

    fn transition(&self, reason: transport::TransitionReason) -> Option<&dyn transport::Transport> {
        UdpTransport.transition(reason)
    }

    fn exchange<'a>(
        &'a self,
        server: std::net::SocketAddr,
        request: &'a Message,
        timeout: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, transport::TransportError>> {
        Box::pin(async move {
            if self.enabled {
                for question in &request.questions {
                    eprintln!(
                        "-> {server} {} {}",
                        output::name(&question.qname),
                        question.qtype
                    );
                }
            }
            let started = Instant::now();
            let response = UdpTransport.exchange(server, request, timeout).await;
            if self.enabled {
                match &response {
                    Ok(message) => eprintln!(
                        "<- {server} {} answers={} authority={} {:.3}ms",
                        output::status(message),
                        message.answers.len(),
                        message.authorities.len(),
                        started.elapsed().as_secs_f64() * 1000.0
                    ),
                    Err(error) => eprintln!("<- {server} {error}"),
                }
            }
            response
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_classes_and_reverse_names() {
        assert_eq!("TYPE28".parse::<QueryType>().unwrap(), QueryType::AAAA);
        assert_eq!(
            "TYPE65".parse::<QueryType>().unwrap(),
            QueryType::Unknown(65)
        );
        assert!("typo".parse::<QueryType>().is_err());
        assert_eq!(
            "CLASS1".parse::<dns::QClassType>().unwrap(),
            dns::QClassType::Class(dns::ClassType::IN)
        );
        assert_eq!(
            reverse("192.0.2.1".parse().unwrap()),
            "1.2.0.192.in-addr.arpa."
        );
        let name = reverse("2001:db8::1".parse().unwrap());
        assert!(name.starts_with("1.0.0.0."));
        assert!(name.ends_with("8.b.d.0.1.0.0.2.ip6.arpa."));
    }
}

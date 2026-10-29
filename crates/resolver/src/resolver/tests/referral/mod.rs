include!("support.rs");

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn record(name: DomainName, rtype: RecordType, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name,
        rtype,
        class: ClassType::IN,
        ttl: 60,
        rdata,
    }
}

fn assert_query(
    actual: &(SocketAddr, DomainName, QueryType),
    server: SocketAddr,
    qname: &DomainName,
    qtype: QueryType,
) {
    assert_eq!(actual.0, server);
    assert!(actual.1.eq_dns(qname));
    assert_eq!(actual.2, qtype);
}

mod glue_and_cname;
mod glueless_and_cache;

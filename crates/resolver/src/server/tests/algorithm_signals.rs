use super::*;
use dns::{DnssecAlgorithmSignal, EdnsOption, FromWire};

#[tokio::test]
async fn reserved_advisory_algorithms_forward_without_panicking_or_leaking_into_responses() {
    for signal in [
        DnssecAlgorithmSignal::Dau,
        DnssecAlgorithmSignal::Dhu,
        DnssecAlgorithmSignal::N3u,
    ] {
        for algorithms in [vec![0], vec![255], vec![0, 8, 255, 8], vec![]] {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let server = RecursiveServer::with_resolver(Resolver::new(
                RecordingAnswerTransport {
                    requests: Arc::clone(&requests),
                },
                ResolverConfig {
                    root_servers: vec![(Ipv4Addr::LOCALHOST, 53).into()],
                    ..ResolverConfig::default()
                },
            ));
            let edns = Edns {
                dnssec_ok: true,
                options: vec![EdnsOption {
                    code: signal.option_code(),
                    data: algorithms.clone(),
                }],
                ..Edns::new(512)
            };
            assert!(edns.validate_options().is_ok());
            let mut query = request(true);
            query.additionals.push(edns.into_record());
            let response = server.answer(&query).await;
            assert_eq!(response.headers.rcode, RCode::Ok);
            assert!(!response.answers.is_empty());
            let sent = requests.lock().unwrap();
            assert_eq!(sent.len(), 1);
            let wire = sent[0].clone().into_wire().unwrap();
            let outbound = Message::from_wire(&wire).unwrap().edns().unwrap().unwrap();
            assert!(outbound.dnssec_ok);
            assert_eq!(
                outbound.algorithm_signal(signal).unwrap(),
                Some(algorithms.as_slice())
            );
            let response_edns = response.edns().unwrap().unwrap();
            assert!(response_edns.dnssec_ok);
            assert_eq!(response_edns.algorithm_signal(signal).unwrap(), None);
        }
    }
}

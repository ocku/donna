use super::*;

#[tokio::test]
async fn preserves_signed_questionless_update_responses() {
    for case in crate::tests::signed_responses::SignedResponse::cases(42) {
        let (address, task) = one_connection_server(case.handler()).await;
        let transport = TlsTransport::new(client_config("localhost"));
        let response = transport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.abort();
    }
}

#[tokio::test]
async fn preserves_inverse_response_discovered_questions() {
    for case in crate::tests::signed_responses::SignedResponse::inverse_cases(42) {
        let (address, task) = one_connection_server(case.handler()).await;
        let transport = TlsTransport::new(client_config("localhost"));
        let response = transport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.abort();
    }
}

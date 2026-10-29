use super::*;

#[tokio::test]
async fn preserves_signed_questionless_update_responses() {
    for method in [DohMethod::Get, DohMethod::Post] {
        for case in crate::tests::signed_responses::SignedResponse::cases(42) {
            let (address, task) = one_connection_server(case.handler()).await;
            let transport = DohTransport::new(client_config(method));
            let response = transport
                .exchange(address, &case.request, Duration::from_secs(2))
                .await
                .unwrap();
            case.verify(&response);
            task.abort();
        }
    }
}

#[tokio::test]
async fn preserves_inverse_response_discovered_questions() {
    for method in [DohMethod::Get, DohMethod::Post] {
        for case in crate::tests::signed_responses::SignedResponse::inverse_cases(42) {
            let (address, task) = one_connection_server(case.handler()).await;
            let transport = DohTransport::new(client_config(method));
            let response = transport
                .exchange(address, &case.request, Duration::from_secs(2))
                .await
                .unwrap();
            case.verify(&response);
            task.abort();
        }
    }
}

use super::*;

#[test]
fn rejects_an_invalid_authentication_name_before_network_io() {
    let mut roots = RootCertStore::empty();
    roots.add(certificate()).unwrap();
    assert!(TlsClientConfig::new(roots, "not a DNS name".to_owned()).is_err());
}

#[test]
fn server_uses_stateless_session_tickets_without_a_session_cache() {
    let config = server_config();

    assert!(config.0.ticketer.enabled());
    assert!(!config.0.session_storage.can_cache());
}

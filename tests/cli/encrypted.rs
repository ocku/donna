use super::support::*;
use serde_json::Value;
use std::{fs, net::TcpListener, process::Command};

#[test]
fn encrypted_listeners_and_clients_verify_identity_and_support_all_protocols() {
    const PROVIDER_SECRET: [u8; 32] = [7; 32];
    const RESOLVER_SECRET: [u8; 32] = [9; 32];
    const PROVIDER_NAME: &str = "2.dnscrypt-cert.example.test";

    let mut f = Fixture::new();
    f.write("zone.db", &zone("192.0.2.85", 1));
    f.write("cert.pem", include_str!("../fixtures/localhost.pem"));
    f.write("key.pem", include_str!("../fixtures/localhost-key.pem"));

    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };

    let provider_key = ed25519_dalek::SigningKey::from_bytes(&PROVIDER_SECRET)
        .verifying_key()
        .to_bytes();
    let resolver_key = *crypto_box::SecretKey::from(RESOLVER_SECRET)
        .public_key()
        .as_bytes();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let cert = transport::DnscryptCertificate::sign(
        &PROVIDER_SECRET,
        resolver_key,
        *b"DONNACLI",
        1,
        now - 60,
        now + 3600,
    )
    .unwrap();
    fs::write(f.directory.join("dnscrypt.cert"), cert.as_bytes()).unwrap();
    f.write("dnscrypt.key", &hex(&RESOLVER_SECRET));

    let mut config = authority(&f);
    let mut ports = Vec::new();

    // Reserve distinct ports together before the daemon takes ownership.
    let reservations: Vec<_> = (0..5)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    for listener in &reservations {
        ports.push(listener.local_addr().unwrap().port());
    }

    for (protocol, port) in ["tls", "https", "quic"].into_iter().zip(&ports) {
        config.push_str(&format!("\n[[listen]]\nprotocol='{protocol}'\naddress='127.0.0.1:{port}'\ncertificate='cert.pem'\nprivate_key='key.pem'\n"));
    }

    for (protocol, port) in ["dnscrypt-udp", "dnscrypt-tcp"]
        .into_iter()
        .zip(&ports[3..])
    {
        config.push_str(&format!("\n[[listen]]\nprotocol='{protocol}'\naddress='127.0.0.1:{port}'\nprovider_name='{PROVIDER_NAME}'\nprovider_key='{}'\ndnscrypt_certificate='dnscrypt.cert'\ndnscrypt_secret_key='dnscrypt.key'\n", hex(&provider_key)));
    }

    drop(reservations);
    f.start(&config);

    for (protocol, port) in ["tls", "https", "quic", "dnscrypt-udp", "dnscrypt-tcp"]
        .into_iter()
        .zip(&ports)
    {
        let mut command = Command::new(BIN);
        command.args([
            "query",
            "www.example.test",
            "--protocol",
            protocol,
            "-s",
            &format!("127.0.0.1:{port}"),
            "--json",
            "--attempts",
            "1",
        ]);

        if protocol.starts_with("dnscrypt") {
            command.args([
                "--provider-name",
                PROVIDER_NAME,
                "--provider-key",
                &hex(&provider_key),
            ]);
        } else {
            command
                .args(["--tls-name", "localhost", "--ca"])
                .arg(f.directory.join("cert.pem"));
        }

        let output = command.output().unwrap();

        assert!(
            output.status.success(),
            "{protocol}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["answers"][0]["data"], "192.0.2.85", "{protocol}");
    }

    let untrusted = Command::new(BIN)
        .args([
            "query",
            "www.example.test",
            "--protocol",
            "tls",
            "-s",
            &format!("127.0.0.1:{}", ports[0]),
            "--tls-name",
            "wrong.example",
            "--ca",
        ])
        .arg(f.directory.join("cert.pem"))
        .args(["--attempts", "1"])
        .output()
        .unwrap();

    assert!(!untrusted.status.success());
}

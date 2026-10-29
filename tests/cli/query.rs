use super::support::*;
use std::{process::Command, thread};

#[test]
fn client_requests_dnssec_by_default_and_allows_explicit_opt_out() {
    use dns::{FromWire, IntoWire};
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(STARTUP_TIMEOUT)).unwrap();
    let address = socket.local_addr().unwrap().to_string();

    let cases: &[(&[&str], Option<bool>, bool)] = &[
        (&[], Some(true), false),
        (&["--dnssec"], Some(true), false),
        (&["--no-dnssec"], Some(false), false),
        (&["--no-edns"], None, false),
        (&["--checking-disabled"], Some(true), true),
    ];
    let count = cases.len();

    let responder = thread::spawn(move || {
        let mut observed = Vec::new();
        let mut packet = [0; transport::MAX_UDP_MESSAGE_OCTETS];

        for _ in 0..count {
            let (length, peer) = socket.recv_from(&mut packet).unwrap();
            let mut message = dns::Message::from_wire(&packet[..length]).unwrap();

            observed.push((
                message.edns().unwrap().map(|edns| edns.dnssec_ok),
                message.headers.cd,
            ));

            message.headers.qr = true;
            message.headers.ra = true;
            socket.send_to(&message.into_wire().unwrap(), peer).unwrap();
        }

        observed
    });

    for (flags, _, _) in cases {
        let output = Command::new(BIN)
            .args([
                "query",
                "example.test",
                "-s",
                &address,
                "--attempts",
                "1",
                "--json",
            ])
            .args(*flags)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{flags:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let observed = responder.join().unwrap();
    for ((flags, dnssec, checking_disabled), actual) in cases.iter().zip(observed) {
        assert_eq!(actual, (*dnssec, *checking_disabled), "{flags:?}");
    }
}

#[test]
fn iterative_cli_resolves_against_explicit_root_and_reports_a_dead_root() {
    let mut root = Fixture::new();
    root.write(
        "root.db",
        "$ORIGIN .\n$TTL 60\n@ IN SOA ns. hostmaster. (1 3600 600 86400 60)\n@ IN NS ns.\nns. IN A 127.0.0.1\nwww.example.test. IN A 192.0.2.87\n",
    );
    root.start(&format!(
        "role='authoritative'\n{}\n[[zones]]\norigin='.'\nfile='root.db'\n",
        root.listeners()
    ));

    let mut command = Command::new(BIN);
    command.args([
        "resolve",
        "www.example.test",
        "--root",
        &format!("127.0.0.1:{}", root.port),
        "--no-validate",
        "--json",
        "--deadline",
        "1",
    ]);

    let response = command.output().unwrap();
    assert!(
        response.status.success(),
        "{}",
        String::from_utf8_lossy(&response.stderr)
    );
    let answer: serde_json::Value = serde_json::from_slice(&response.stdout).unwrap();
    assert_eq!(answer["answers"][0]["data"], "192.0.2.87");
    assert_eq!(answer["questions"][0]["name"], "www.example.test.");

    root.stop();
    let response = command.output().unwrap();
    assert!(!response.status.success());
}

use super::support::*;
use serde_json::Value;
use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[test]
fn binary_serves_authoritative_udp_tcp_and_axfr_and_rejects_bad_config() {
    let mut f = Fixture::new();
    f.write("zone.db", &zone("192.0.2.80", 1));
    f.start(&authority(&f));

    for protocol in ["udp", "tcp"] {
        let answer = f.query("www.example.test", protocol);

        assert_eq!(answer["answers"][0]["data"], "192.0.2.80");
        assert_eq!(answer["flags"]["aa"], true);
        assert_eq!(answer["flags"]["ra"], false);
    }
    assert_eq!(f.query("absent.example.test", "udp")["status"], "NameError");

    let transfer = Command::new(BIN)
        .args([
            "query",
            "example.test",
            "AXFR",
            "--protocol",
            "tcp",
            "-s",
            &format!("127.0.0.1:{}", f.port),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        transfer.status.success(),
        "{}",
        String::from_utf8_lossy(&transfer.stderr)
    );
    let transfer: Value = serde_json::from_slice(&transfer.stdout).unwrap();
    assert!(transfer["answers"].as_array().unwrap().len() >= 4);

    f.write("bad.toml", "role='authoritative'\nunknown=true");
    let check = Command::new(BIN)
        .args(["check", "-c"])
        .arg(f.directory.join("bad.toml"))
        .output()
        .unwrap();

    assert!(!check.status.success());
}

#[test]
fn forwarding_fails_over_then_serves_cached_answers_and_negatives() {
    let mut peer = Fixture::new();
    peer.write("zone.db", &zone("192.0.2.81", 1));
    peer.start(&authority(&peer));

    let mut forwarder = Fixture::new();
    let config = format!(
        "role='forward'\n{}\n[resolver]\ntimeout_secs=1\nmax_attempts_per_server=1\n[[upstream]]\naddress='127.0.0.1:9'\n[[upstream]]\naddress='127.0.0.1:{}'\n",
        forwarder.listeners(),
        peer.port
    );
    forwarder.start(&config);

    let response = forwarder.query("www.example.test", "udp");

    assert_eq!(response["answers"][0]["data"], "192.0.2.81");
    assert_eq!(response["flags"]["aa"], false);
    assert_eq!(response["flags"]["ra"], true);
    assert_eq!(
        forwarder.query("absent.example.test", "udp")["status"],
        "NameError"
    );

    peer.stop();

    assert_eq!(
        forwarder.query("www.example.test", "udp")["answers"][0]["data"],
        "192.0.2.81"
    );
    assert_eq!(
        forwarder.query("absent.example.test", "udp")["status"],
        "NameError"
    );
}

#[test]
fn recursive_mode_uses_configured_roots_and_enforces_acl() {
    let mut root = Fixture::new();
    root.write("root.db", "$ORIGIN .\n$TTL 60\n@ IN SOA ns. hostmaster. (1 3600 600 86400 60)\n@ IN NS ns.\nns. IN A 127.0.0.1\nwww.example.test. IN A 192.0.2.82\n");
    root.start(&format!(
        "role='authoritative'\n{}\n[[zones]]\norigin='.'\nfile='root.db'\n",
        root.listeners()
    ));

    let mut recursive = Fixture::new();
    recursive.start(&format!(
        "role='recursive'\n{}\n[resolver]\nvalidate=false\nroot_servers=['127.0.0.1:{}']\n",
        recursive.listeners(),
        root.port
    ));

    assert_eq!(
        recursive.query("www.example.test", "tcp")["answers"][0]["data"],
        "192.0.2.82"
    );

    let mut denied = Fixture::new();
    denied.start(&format!(
        "role='recursive'\n{}\n[access]\nrecursion=[]\n",
        denied.listeners()
    ));

    let answer = denied.query_output("www.example.test", "udp");

    assert!(!answer.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&answer.stdout).unwrap()["status"],
        "Refused"
    );
}

#[cfg(unix)]
#[test]
fn reload_replaces_zones_atomically_and_invalid_reload_preserves_service() {
    let mut f = Fixture::new();
    f.write("zone.db", &zone("192.0.2.83", 1));
    f.start(&authority(&f));

    f.write("zone.db", &zone("192.0.2.84", 2));
    let pid = f.child.as_ref().unwrap().id().to_string();
    assert!(
        Command::new("kill")
            .args(["-HUP", &pid])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + STARTUP_TIMEOUT;

    loop {
        if f.query("www.example.test", "udp")["answers"][0]["data"] == "192.0.2.84" {
            break;
        }

        assert!(Instant::now() < deadline, "reload timed out");
        thread::sleep(POLL_INTERVAL);
    }

    f.write("donna.toml", "invalid=true");
    assert!(
        Command::new("kill")
            .args(["-HUP", &pid])
            .status()
            .unwrap()
            .success()
    );
    thread::sleep(Duration::from_millis(100));

    assert_eq!(
        f.query("www.example.test", "tcp")["answers"][0]["data"],
        "192.0.2.84"
    );

    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + STARTUP_TIMEOUT;

    loop {
        if let Some(status) = f.child.as_mut().unwrap().try_wait().unwrap() {
            assert!(status.success());
            break;
        }

        assert!(Instant::now() < deadline, "shutdown timed out");
        thread::sleep(POLL_INTERVAL);
    }

    f.child.take();
}

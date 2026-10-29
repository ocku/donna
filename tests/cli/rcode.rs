//! Independent wire replies keep extended RCODEs distinct from their low bits.

use super::support::{BIN, POLL_INTERVAL};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
};

struct Upstream {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Upstream {
    fn new(code: u16) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(POLL_INTERVAL)).unwrap();
        let address = socket.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_calls = calls.clone();
        let worker_stopped = stopped.clone();

        let worker = thread::spawn(move || {
            let mut packet = [0; transport::MAX_UDP_MESSAGE_OCTETS];
            while !worker_stopped.load(Ordering::SeqCst) {
                match socket.recv_from(&mut packet) {
                    Ok((length, peer)) => {
                        worker_calls.fetch_add(1, Ordering::SeqCst);
                        socket
                            .send_to(&reply(&packet[..length], code), peer)
                            .unwrap();
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => panic!("upstream receive failed: {error}"),
                }
            }
        });

        Self {
            address,
            calls,
            stopped,
            worker: Some(worker),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn reply(query: &[u8], code: u16) -> Vec<u8> {
    // Copy just the independently parsed question, then construct the header
    // and OPT bytes without Donna's encoder or RCODE helpers.
    let mut end = 12;
    while query[end] != 0 {
        end += usize::from(query[end]) + 1;
    }
    end += 5;
    let mut response = query[..end].to_vec();
    response[2] = 0x81; // QR and RD.
    response[3] = 0x80 | (code as u8 & 0x0f); // RA and low RCODE bits.
    response[6..10].fill(0);
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[
        0,
        0,
        41, // Root owner and OPT.
        4,
        208, // UDP payload 1232.
        (code >> 4) as u8,
        0,
        0,
        0, // Extended RCODE, version, flags.
        0,
        0, // Empty options.
    ]);
    response
}

fn query(first: &Upstream, second: &Upstream, flags: &[&str]) -> Output {
    let output = Command::new(BIN)
        .args([
            "query",
            "example.test",
            "--server",
            &first.address.to_string(),
            "--server",
            &second.address.to_string(),
            "--attempts",
            "1",
            "--timeout",
            "1",
            "--deadline",
            "3",
        ])
        .args(flags)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn full_rcodes_control_reported_status_and_failover() {
    for (code, expected_status, failover) in [
        (0, "Ok", false),
        (3, "NameError", false),
        (16, "RCODE16", false),
        (34, "RCODE34", false),
        (37, "RCODE37", false),
        (2, "Ok", true),
        (5, "Ok", true),
    ] {
        let first = Upstream::new(code);
        let second = Upstream::new(0);
        let output = query(&first, &second, &["--json"]);
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

        assert_eq!(response["status"], expected_status, "RCODE {code}");
        assert_eq!(response["rcode"], if failover { 0 } else { code });
        assert_eq!(first.calls(), 1, "RCODE {code}");
        assert_eq!(second.calls(), usize::from(failover), "RCODE {code}");
    }
}

#[test]
fn text_and_comparison_keep_extended_errors_distinct() {
    for code in [16, 34, 37] {
        let first = Upstream::new(code);
        let second = Upstream::new(0);
        let output = query(&first, &second, &[]);
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!(";; status: RCODE{code} ({code})"))
        );
        assert_eq!(second.calls(), 0);

        let output = query(&first, &second, &["--compare", "--json"]);
        let responses: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["status"], format!("RCODE{code}"));
        assert_eq!(responses[0]["rcode"], code);
        assert_eq!(responses[1]["status"], "Ok");
        assert_eq!(first.calls(), 2);
        assert_eq!(second.calls(), 1);
    }
}

use serde_json::Value;
use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(super) const BIN: &str = env!("CARGO_BIN_EXE_donna");
pub(super) const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(30);

pub(super) struct Fixture {
    pub directory: PathBuf,
    pub child: Option<Child>,
    pub port: u16,
}

impl Fixture {
    pub fn new() -> Self {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();

        let directory = std::env::temp_dir().join(format!(
            "donna-cli-{}-{:x}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        fs::create_dir(&directory).unwrap();

        Self {
            directory,
            child: None,
            port,
        }
    }

    pub fn write(&self, file: &str, contents: &str) {
        fs::write(self.directory.join(file), contents).unwrap();
    }

    pub fn listeners(&self) -> String {
        format!(
            "[[listen]]\nprotocol='udp'\naddress='127.0.0.1:{}'\n[[listen]]\nprotocol='tcp'\naddress='127.0.0.1:{}'\n",
            self.port, self.port
        )
    }

    pub fn start(&mut self, config: &str) {
        self.start_with_verbosity(config, false);
    }

    pub fn start_with_verbosity(&mut self, config: &str, verbose: bool) {
        self.write("donna.toml", config);

        let check = Command::new(BIN)
            .args(["check", "-c"])
            .arg(self.directory.join("donna.toml"))
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "{}",
            String::from_utf8_lossy(&check.stderr)
        );

        let mut command = Command::new(BIN);
        command
            .arg("-c")
            .arg(self.directory.join("donna.toml"))
            .env_remove("RUST_LOG")
            .stdout(Stdio::null())
            .stderr(fs::File::create(self.directory.join("stderr.log")).unwrap());
        if verbose {
            command.arg("--verbose");
        }
        self.child = Some(command.spawn().unwrap());

        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                break;
            }

            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "daemon exited during startup"
            );
            assert!(Instant::now() < deadline, "daemon startup timed out");
            thread::sleep(POLL_INTERVAL);
        }
    }

    pub fn stderr(&self) -> String {
        fs::read_to_string(self.directory.join("stderr.log")).unwrap()
    }

    pub fn query(&self, name: &str, protocol: &str) -> Value {
        let output = self.query_output(name, protocol);

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        serde_json::from_slice(&output.stdout).unwrap()
    }

    pub fn query_output(&self, name: &str, protocol: &str) -> Output {
        Command::new(BIN)
            .args([
                "query",
                name,
                "--protocol",
                protocol,
                "-s",
                &format!("127.0.0.1:{}", self.port),
                "--json",
                "--attempts",
                "1",
                "--timeout",
                "1",
                "--deadline",
                "3",
            ])
            .output()
            .unwrap()
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub(super) fn zone(address: &str, serial: u32) -> String {
    format!(
        "$ORIGIN example.test.\n$TTL 60\n@ IN SOA ns hostmaster ({serial} 3600 600 86400 60)\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A {address}\n"
    )
}

pub(super) fn authority(fixture: &Fixture) -> String {
    format!(
        "role='authoritative'\n{}\n[[zones]]\norigin='example.test.'\nfile='zone.db'\n[authority]\nallow_transfer=['127.0.0.0/8']\n",
        fixture.listeners()
    )
}

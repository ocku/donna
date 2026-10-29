#!/usr/bin/env python3
"""Generate private counters over an immutable current source snapshot."""

import argparse
import hashlib
import json
from support.paths import SUITE
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("overlay", type=Path)
    args = parser.parse_args()
    manifest = {}

    def patch(path, replacements):
        text = (args.source / path).read_text()
        for old, new in replacements:
            assert text.count(old) == 1, (path, old, text.count(old))
            text = text.replace(old, new, 1)
        destination = args.overlay / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
        manifest[path] = hashlib.sha256(destination.read_bytes()).hexdigest()

    patch(
        "crates/transport/src/udp/mod.rs",
        [("mod response;", "mod response;\nmod profile;")],
    )
    patch(
        "crates/transport/src/lib.rs",
        [
            (
                "pub use udp::UdpTransport;",
                'pub use udp::UdpTransport;\n/// Returns aggregate private instrumentation counters between load runs.\n#[cfg(feature = "udp")]\npub fn udp_batch_profile_snapshot() -> String { udp::profile::snapshot() }',
            )
        ],
    )
    # Make only the profiler module visible to the parent crate export.
    path = args.overlay / "crates/transport/src/udp/mod.rs"
    path.write_text(path.read_text().replace("mod profile;", "pub(crate) mod profile;"))
    manifest[str(path.relative_to(args.overlay))] = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    patch(
        "crates/transport/src/udp/batch.rs",
        [
            (
                "            Ok(count) => count,",
                "            Ok(count) => { super::profile::received(count); count },",
            ),
            (
                "            {\n                continue;\n            }\n            Err(error)",
                "            {\n                super::profile::add(if error.kind() == io::ErrorKind::WouldBlock { super::profile::RX_WOULD_BLOCK } else { super::profile::RX_INTERRUPTED });\n                continue;\n            }\n            Err(error)",
            ),
            (
                "                if first_ready {",
                "                super::profile::add(super::profile::PREPARED);\n                if first_ready {",
            ),
            (
                "                    if reply.deadline <= tokio::time::Instant::now() {",
                "                    if reply.deadline <= tokio::time::Instant::now() {\n                        super::profile::add(super::profile::FIRST_EXPIRED);",
            ),
            (
                "                    match socket.try_send_to(&reply.wire, reply.peer) {",
                "                    super::profile::add(super::profile::FIRST_ATTEMPT);\n                    match socket.try_send_to(&reply.wire, reply.peer) {",
            ),
            (
                "                        Ok(_) => continue,",
                "                        Ok(_) => { super::profile::add(super::profile::FIRST_SENT); continue; },",
            ),
            (
                '                            tracing::debug!(%peer, ?error, "UDP response send failed");',
                '                            super::profile::add(super::profile::FIRST_ERROR);\n                            tracing::debug!(%peer, ?error, "UDP response send failed");',
            ),
            (
                "                        Err(_) => {}",
                "                        Err(_) => { super::profile::add(super::profile::FIRST_WOULD_BLOCK); }",
            ),
            (
                "        if !replies.is_empty() {",
                "        if !replies.is_empty() {\n            super::profile::dispatch(replies.len());",
            ),
            (
                "    let received = recvmmsg(",
                "    super::profile::add(super::profile::RX_CALL);\n    let received = recvmmsg(",
            ),
        ],
    )
    patch(
        "crates/transport/src/udp/server.rs",
        [
            (
                "        Ok(super::response::PacketResponse::Ready(wire)) => {",
                "        Ok(super::response::PacketResponse::Ready(wire)) => {\n            super::profile::add(if wire.is_some() { super::profile::SYNC_SOME } else { super::profile::SYNC_NONE });",
            ),
            (
                "        Ok(super::response::PacketResponse::Deferred(query)) => query,",
                "        Ok(super::response::PacketResponse::Deferred(query)) => { super::profile::add(super::profile::DEFERRED); query },",
            ),
            (
                "        Ok(std::task::Poll::Ready(reply)) => reply,",
                "        Ok(std::task::Poll::Ready(reply)) => { super::profile::add(super::profile::DEFERRED_READY); reply },",
            ),
            (
                "        Ok(std::task::Poll::Pending) => {\n            let socket = Arc::clone(socket);",
                "        Ok(std::task::Poll::Pending) => {\n            super::profile::add(super::profile::DEFERRED_PENDING);\n            let socket = Arc::clone(socket);",
            ),
        ],
    )
    patch(
        "crates/transport/src/udp/send.rs",
        [
            (
                "    let sent = unsafe {",
                "    super::profile::send(count);\n    let sent = unsafe {",
            ),
            (
                "    if sent < 0 {\n        Err(io::Error::last_os_error())",
                "    if sent < 0 {\n        super::profile::add(super::profile::SEND_ERROR);\n        Err(io::Error::last_os_error())",
            ),
            (
                "        Ok(sent as usize)\n    }",
                "        super::profile::committed(sent as usize);\n        Ok(sent as usize)\n    }",
            ),
        ],
    )
    patch(
        "examples/authority/src/listeners.rs",
        [
            (
                "async fn main() -> Result<(), Failure> {",
                """async fn main() -> Result<(), Failure> {
    let mut profile_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    tokio::spawn(async move {
        while profile_signal.recv().await.is_some() {
            eprintln!("UDP_BATCH_PROFILE {}", transport::udp_batch_profile_snapshot());
        }
    });""",
            )
        ],
    )
    module = SUITE / "profile/batch_counts.rs"
    target = args.overlay / "crates/transport/src/udp/profile.rs"
    target.write_bytes(module.read_bytes())
    manifest[str(target.relative_to(args.overlay))] = hashlib.sha256(
        target.read_bytes()
    ).hexdigest()
    args.overlay.joinpath("overlay-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()

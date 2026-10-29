# Linux batch-send portability probe

This Linux probe copies the current Donna `udp/send.rs` and runs its six
tests with a small packet adapter. The adapter reproduces the test packet
fields, permit lifetime, deadline check and individual-send fallback. It does
not exercise the complete transport server, so these checks supplement the
full transport tests.

The harness also builds directly from a Linux source checkout:

```sh
cargo check --locked --manifest-path examples/interop/portability/Cargo.toml --all-targets
cargo test --locked --manifest-path examples/interop/portability/Cargo.toml
```

It includes `crates/transport/src/udp/send.rs` by a relative source path, so the
isolated Docker copy below retains that directory layout. On non-Linux hosts
its Linux module is excluded; use Docker to exercise the batch-send tests.

`inject_sendmmsg.c` is a test-only `LD_PRELOAD` interposer. `EINTR` fails the
first `sendmmsg` call; `EAGAIN` fails it and has a separate thread send an empty
loopback datagram after 100 ms to generate a later writable event. This is an
artificial fault and wakeup, not live socket backpressure. `EAGAIN_NO_WAKE`
intentionally omits the readiness event and demonstrates that an artificial
`EAGAIN` on a socket that remains writable does not establish kernel readiness
behavior. Never load this interposer into a production process.

Run this block from the repository root. It uses Docker's native Linux
architecture, records the copied source and harness hashes, and removes its
container on exit. Dependencies come from the checked-in lockfile. The small
release-profile harness uses no LTO and one compiler job; Docker may fetch
already locked packages. No generated report or historical archive is needed.

```sh
(
  set -eu
  docker create --name donna-send-probe rust:bookworm sleep infinity
  trap 'docker rm -f donna-send-probe >/dev/null' EXIT
  docker start donna-send-probe
  docker exec donna-send-probe mkdir -p /source/crates/transport/src/udp /source/examples/interop/portability
  docker cp crates/transport/src/udp/send.rs donna-send-probe:/source/crates/transport/src/udp/send.rs
  docker cp examples/interop/portability/. donna-send-probe:/source/examples/interop/portability/
  docker exec donna-send-probe uname -m
  docker exec donna-send-probe rustc --version
  docker exec donna-send-probe sha256sum \
    /source/crates/transport/src/udp/send.rs \
    /source/examples/interop/portability/Cargo.lock /source/examples/interop/portability/send_harness.rs /source/examples/interop/portability/udp.rs \
    /source/examples/interop/portability/inject_sendmmsg.c
  docker exec -w /source/examples/interop/portability -e CARGO_INCREMENTAL=0 -e CARGO_BUILD_JOBS=1 \
    donna-send-probe cargo test --locked --release --no-run
  docker exec -w /source/examples/interop/portability donna-send-probe \
    cc -shared -fPIC -O2 -Wall -Wextra -Werror -pthread inject_sendmmsg.c -o inject.so
  probe_binary="$(docker exec donna-send-probe find /source/examples/interop/portability/target/release/deps \
    -maxdepth 1 -name 'send_portability-*' -type f -executable -print -quit)"
  test -n "$probe_binary"
  docker exec donna-send-probe "$probe_binary" --test-threads=1
  for mode in EINTR EAGAIN; do
    docker exec -e LD_PRELOAD=/source/examples/interop/portability/inject.so -e DONNA_SEND_INJECT="$mode" \
      donna-send-probe "$probe_binary" \
      --exact udp::send::tests::sends_separate_datagrams_and_preserves_source_for_both_families \
      --nocapture
  done
)
```

To inspect an archived revision, explicitly copy that revision's `send.rs`
instead and retain the printed hashes with the results. Check that the adapter
matches that revision's packet interface. Add `--platform linux/amd64` to
`docker create` to select x86_64, including emulation on an ARM host; record the
platform when comparing runs. No historical platform results are bundled here.

The `EAGAIN` helper sends its empty datagram to UDP port 9 in the container's
own loopback network namespace; it never contacts an external server. These
checks make no performance or general portability claim. They do not model all
races, partial sends combined with faults, or real kernel `EAGAIN` and `EINTR`
events. Native x86, musl and 32-bit execution need their own validation.

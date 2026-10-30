ARG RUST_IMAGE=rust:bookworm

FROM ${RUST_IMAGE} AS builder

WORKDIR /source

COPY Cargo.toml Cargo.lock ./
COPY src src
COPY crates crates
COPY vendor vendor
COPY examples examples

RUN cargo build --locked --release --manifest-path examples/Cargo.toml \
    -p donna-example-adblock --bin adblock

# Keep the upstream notices and license alongside the unmodified domain list.
FROM debian:bookworm-slim AS blocklist

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ARG BLOCKLIST_REF=main

RUN curl --fail --show-error --silent --location --retry 3 \
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/${BLOCKLIST_REF}/wildcard/popupads-onlydomains.txt" \
        -o /blocklist.txt \
    && curl --fail --show-error --silent --location --retry 3 \
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/${BLOCKLIST_REF}/LICENSE" \
        -o /HAGEZI-LICENSE

FROM debian:bookworm-slim

COPY --from=builder /source/examples/target/release/adblock /usr/local/bin/adblock
COPY --from=blocklist /blocklist.txt /etc/donna/blocklist.txt
COPY --from=blocklist /HAGEZI-LICENSE /usr/share/licenses/hagezi/LICENSE
COPY LICENSE NOTICE /usr/share/licenses/donna/
COPY examples/adblock/entrypoint.sh /usr/local/bin/adblock-entrypoint

ENV UPSTREAM_ADDRS=9.9.9.9:853,149.112.112.112:853 \
    BLOCKLIST_FILE=/etc/donna/blocklist.txt

USER 65532:65532

EXPOSE 5353/udp 5353/tcp

ENTRYPOINT ["/bin/sh", "/usr/local/bin/adblock-entrypoint"]

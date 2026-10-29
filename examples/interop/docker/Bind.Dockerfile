FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9 \
        bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY examples/interop /suite

CMD ["named", "-g", "-c", "/suite/fixtures/basic/named.conf", "-u", "root"]

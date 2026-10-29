FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9 \
    && rm -rf /var/lib/apt/lists/*

COPY examples/interop/fixtures/cache/reference.conf /suite/cache-reference.conf
COPY examples/interop/fixtures/cache/root.hints /suite/cache-root.hints

CMD ["named", "-g", "-n", "2", "-c", "/suite/cache-reference.conf", "-u", "root"]

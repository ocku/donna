FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends unbound \
    && rm -rf /var/lib/apt/lists/*

CMD ["unbound", "-d", "-c", "/bench/unbound.conf"]

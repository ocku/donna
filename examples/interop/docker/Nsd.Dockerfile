# Upstream NSD release, with the SHA-256 published by NLnet Labs.
FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        libevent-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl -fsSLo nsd.tar.gz https://www.nlnetlabs.nl/downloads/nsd/nsd-4.15.4.tar.gz \
    && echo '74a095fdb774a157c8aec9009e440fc3d2ba94c4372ae9ed86588c1719d1df2f  nsd.tar.gz' | sha256sum -c - \
    && tar -xzf nsd.tar.gz

WORKDIR /build/nsd-4.15.4
RUN ./configure \
        --prefix=/usr/local \
        --disable-dnstap \
        --disable-systemd \
        --enable-reuseport \
        --with-libevent \
    && make -j2 \
    && make install DESTDIR=/out

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libevent-2.1-7 \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/usr/local /usr/local

CMD ["nsd", "-d", "-c", "/work/nsd.conf"]

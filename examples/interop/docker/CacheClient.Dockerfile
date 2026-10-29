FROM debian:bookworm-slim AS batched-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY examples/interop/python/batched_load.c /tmp/batched_load.c
RUN gcc -O3 -std=c11 -Wall -Wextra -Werror \
    /tmp/batched_load.c -o /tmp/batched_load

FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dnsperf \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir dnspython==2.8.0

COPY --from=batched-builder /tmp/batched_load /usr/local/bin/batched_load

COPY examples/interop/python/authority_load.py \
    examples/interop/python/batched_load_test.py \
    examples/interop/python/cache_load.py \
    examples/interop/python/cache_network.py \
    examples/interop/python/cold_load.py \
    /suite/

ENTRYPOINT ["python", "/suite/cache_network.py"]

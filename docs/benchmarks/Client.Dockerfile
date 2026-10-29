FROM debian:bookworm-slim AS native
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY examples/interop/python/batched_load.c /tmp/batched_load.c
RUN gcc -O3 -std=c11 -Wall -Wextra -Werror /tmp/batched_load.c -o /tmp/batched_load

FROM donna-docs:local AS donna
FROM donna-interop-cache-client
RUN apt-get update && apt-get install -y --no-install-recommends bind9-dnsutils && rm -rf /var/lib/apt/lists/*
COPY --from=native /tmp/batched_load /usr/local/bin/batched_load
COPY --from=donna /usr/local/bin/donna /usr/local/bin/donna
COPY examples/interop/python/cache_load.py /suite/cache_load.py
COPY docs/benchmarks/worker.py /suite/documentation_worker.py
COPY docs/benchmarks/test_worker.py /suite/test_documentation_worker.py
ENTRYPOINT ["python", "/suite/documentation_worker.py"]

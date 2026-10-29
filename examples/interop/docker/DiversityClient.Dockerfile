ARG NATIVE_BUILDER=rust:bookworm
ARG CLIENT_BASE=donna-interop-cache-client-body:local

FROM ${NATIVE_BUILDER} AS native

COPY examples/interop/python/batched_load.c /tmp/batched_load.c
RUN gcc -O3 -std=c11 -Wall -Wextra -Werror \
    /tmp/batched_load.c -o /tmp/batched_load

FROM ${CLIENT_BASE}

COPY --from=native /tmp/batched_load /usr/local/bin/batched_load

COPY examples/interop/python/batched_load_test.py \
    examples/interop/python/diversity_fixture.py \
    examples/interop/python/diversity_load.py \
    examples/interop/python/diversity_load_test.py \
    examples/interop/python/diversity_replay.py \
    examples/interop/python/diversity_replay_test.py \
    examples/interop/support/server_cpu.py \
    /suite/

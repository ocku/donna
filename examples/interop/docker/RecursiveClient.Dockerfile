ARG NATIVE_BUILDER=rust:bookworm
ARG CLIENT_BASE=donna-interop-authority-client-body:local

FROM ${NATIVE_BUILDER} AS native

COPY examples/interop/python/batched_load.c /tmp/batched_load.c
COPY examples/interop/python/clock_snapshot_test.c /tmp/clock_snapshot_test.c

RUN gcc -O3 -std=c11 -Wall -Wextra -Werror \
        /tmp/batched_load.c -o /tmp/batched_load \
    && gcc -O3 -std=c11 -Wall -Wextra -Werror \
        -DDONNA_CLOCK_TEST_END_DELAY_US=600000 \
        /tmp/batched_load.c -o /tmp/batched_load_clock_delay \
    && gcc -O3 -std=c11 -Wall -Wextra -Werror \
        /tmp/clock_snapshot_test.c -o /tmp/clock_snapshot_test

FROM ${CLIENT_BASE}

COPY --from=native \
    /tmp/batched_load \
    /tmp/batched_load_clock_delay \
    /tmp/clock_snapshot_test \
    /usr/local/bin/

COPY examples/interop/python/batched_capture_test.py \
    examples/interop/python/batched_load_test.py \
    examples/interop/python/capture_budget_test.py \
    examples/interop/python/clock_capture_test.py \
    examples/interop/python/recursive_capture.py \
    /suite/

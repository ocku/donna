/* Compile-time clock injection exercises the actual bounded sampler. */
#define main benchmark_main
#define clock_gettime injected_clock_gettime
#include "batched_load.c"
#undef clock_gettime
#undef main

static const char *scenario;
static unsigned calls;

int injected_clock_gettime(clockid_t clock, struct timespec *value) {
    unsigned attempt = calls / 3, position = calls++ % 3;
    if (clock != (position == 1 ? CLOCK_REALTIME : CLOCK_MONOTONIC)) abort();
    bool wide = !strcmp(scenario, "exhausted") ||
                (!strcmp(scenario, "retry") && attempt == 0) ||
                (!strcmp(scenario, "last") && attempt < 7);
    uint64_t base = 1000000000 + (uint64_t)attempt * 10000000;
    uint64_t ticks = position == 0 ? base : position == 1 ?
        1700000000000000000 + base + 100 : base + (wide ? 2000000 : 200);
    value->tv_sec = (time_t)(ticks / NANOSECONDS_PER_SECOND);
    value->tv_nsec = (long)(ticks % NANOSECONDS_PER_SECOND);
    return 0;
}

static void report_calls(void) { fprintf(stderr, "clock_calls=%u\n", calls); }

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    scenario = argv[1];
    atexit(report_calls);
    struct ClockSnapshot sample = clock_snapshot();
    printf("{\"attempts\":%u,\"span_ns\":%llu,\"uncertainty_ns\":%llu,\"monotonic_ns\":%llu}\n",
           sample.attempts, (unsigned long long)sample.span_ns,
           (unsigned long long)sample.uncertainty_ns, (unsigned long long)sample.monotonic_ns);
    return 0;
}

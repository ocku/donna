#define _GNU_SOURCE
/* Diagnostic Linux UDP load generator. One repeated query, a cyclic pool or a finite exact list, 32 in flight.
 * The Python driver performs full DNS policy checks before and after timing.
 * Every timed response must match its pending ID, question and expected flags.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { WINDOW = 32, MAX_WIRE = 65535, MAX_QUERIES = 2048 };
enum {
    NANOSECONDS_PER_SECOND = 1000000000,
    CLOCK_SNAPSHOT_ATTEMPTS = 8,
    CLOCK_MAX_BRACKET_NS = 1000000,
    CLOCK_RESOLUTION_ALLOWANCE_NS = 1000,
};

struct Input {
    unsigned char *wire, *expected;
    size_t size, question_end, expected_size;
};

static struct Input inputs[MAX_QUERIES];
static unsigned char replies[WINDOW][MAX_WIRE];
static unsigned char queries[WINDOW][MAX_WIRE];
static unsigned char expected_reply[MAX_WIRE];
enum { CAPTURE_DEFAULT = 128 * 1024 * 1024, CAPTURE_MAX = 512 * 1024 * 1024 };
static size_t capture_budget = CAPTURE_DEFAULT;
static unsigned char *capture_stream;
static size_t capture_size;

static void fail(const char *message) {
    fprintf(stderr, "batched_load: %s (%s)\n", message, strerror(errno));
    exit(1);
}

static double seconds_clock(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) fail("clock_gettime");
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static double now(void) { return seconds_clock(CLOCK_MONOTONIC); }

struct ClockSnapshot {
    uint64_t monotonic_ns, wall_ns, span_ns, uncertainty_ns;
    unsigned attempts;
};

static uint64_t nanoseconds_clock(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t) || t.tv_sec < 0) fail("clock_gettime nanoseconds");
    return (uint64_t)t.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)t.tv_nsec;
}

static struct ClockSnapshot clock_snapshot(void) {
    for (unsigned attempt = 1; attempt <= CLOCK_SNAPSHOT_ATTEMPTS; attempt++) {
        uint64_t before = nanoseconds_clock(CLOCK_MONOTONIC);
        uint64_t wall = nanoseconds_clock(CLOCK_REALTIME);
        uint64_t after = nanoseconds_clock(CLOCK_MONOTONIC);
        if (after >= before && after - before <= CLOCK_MAX_BRACKET_NS) {
            uint64_t span = after - before;
            return (struct ClockSnapshot){before + span / 2, wall, span,
                                           (span + 1) / 2 + CLOCK_RESOLUTION_ALLOWANCE_NS,
                                           attempt};
        }
    }
    fail("clock snapshot exceeded bounded bracket");
    return (struct ClockSnapshot){0};
}

static unsigned word(const unsigned char *p) {
    return ((unsigned)p[0] << 8) | p[1];
}

static size_t question_end(const unsigned char *wire, size_t size) {
    if (size < 17 || word(wire + 4) != 1 || (wire[2] & 0x80)) fail("query header/size");
    size_t end = 12;
    while (end < size && wire[end]) {
        unsigned n = wire[end];
        if (n > 63 || end + n + 1 >= size) fail("query label");
        end += n + 1;
    }
    end += 5;
    if (end > size) fail("query question");
    return end;
}

static unsigned load_queries(FILE *file, bool list) {
    unsigned count = 0;
    if (!list) {
        size_t size = fread(queries[0], 1, MAX_WIRE, file);
        if (ferror(file) || fgetc(file) != EOF) fail("query file");
        inputs[0].wire = malloc(size);
        if (!inputs[0].wire) fail("allocate query");
        memcpy(inputs[0].wire, queries[0], size);
        inputs[0].size = size;
        inputs[0].question_end = question_end(inputs[0].wire, size);
        return 1;
    }
    while (true) {
        unsigned char prefix[2];
        size_t n = fread(prefix, 1, 2, file);
        if (n == 0 && feof(file)) break;
        if (n != 2 || count == MAX_QUERIES) fail("query list length/count");
        size_t size = word(prefix);
        if (size < 17) fail("query list size");
        struct Input *input = &inputs[count++];
        input->wire = malloc(size);
        if (!input->wire) fail("allocate query");
        if (fread(input->wire, 1, size, file) != size) fail("query list truncation");
        input->size = size;
        input->question_end = question_end(input->wire, size);
    }
    if (!count || ferror(file)) fail("empty/invalid query list");
    return count;
}

static void load_references(const char *path, unsigned population, unsigned flags) {
    FILE *file = fopen(path, "rb");
    if (!file) fail("open expected responses");
    size_t total = 0;
    for (unsigned i = 0; i < population; i++) {
        unsigned char prefix[2];
        if (fread(prefix, 1, 2, file) != 2) fail("expected responses count");
        struct Input *input = &inputs[i];
        size_t size = word(prefix);
        total += size;
        if (size < input->question_end || total > 16 * 1024 * 1024) fail("expected responses size");
        input->expected = malloc(size);
        if (!input->expected) fail("allocate expected response");
        if (fread(input->expected, 1, size, file) != size) fail("expected responses truncation");
        input->expected_size = size;
        if (word(input->expected + 2) != flags || word(input->expected + 4) != 1 ||
            memcmp(input->expected + 12, input->wire + 12, input->question_end - 12))
            fail("expected response flags or question mismatch");
    }
    if (fgetc(file) != EOF || ferror(file)) fail("expected responses count");
    fclose(file);
}

static void write_integer(FILE *file, uint64_t value, unsigned size) {
    unsigned char bytes[8];
    for (unsigned i = 0; i < size; i++) bytes[size - i - 1] = (unsigned char)(value >> (8 * i));
    if (fwrite(bytes, 1, size, file) != size) fail("write capture metadata");
}

static void append_capture_integer(uint64_t value, unsigned size) {
    for (unsigned i = 0; i < size; i++)
        capture_stream[capture_size + size - i - 1] = (unsigned char)(value >> (8 * i));
    capture_size += size;
}

static void capture_response(unsigned index, unsigned id, const unsigned char *wire,
                             size_t size, uint64_t elapsed_ns) {
    if (14 + size > capture_budget - capture_size) fail("response capture capacity exceeded");
    append_capture_integer(index, 2);
    append_capture_integer(id, 2);
    append_capture_integer(size, 2);
    append_capture_integer(elapsed_ns, 8);
    memcpy(capture_stream + capture_size, wire, size);
    capture_size += size;
}

static uint64_t write_capture(const char *path, unsigned population, uint64_t completed,
                              const struct ClockSnapshot *start) {
    if (!path) return 0;
    FILE *file = fopen(path, "wb");
    if (!file) fail("open capture output");
    if (fwrite("DNSCAP03", 1, 8, file) != 8) fail("write capture header");
    write_integer(file, population, 2);
    write_integer(file, start->wall_ns, 8);
    write_integer(file, start->monotonic_ns, 8);
    write_integer(file, completed, 8);
    if (fwrite(capture_stream, 1, capture_size, file) != capture_size) fail("write captured responses");
    if (fclose(file)) fail("close capture output");
    return 34 + capture_size;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: batched_load IPv4 port seconds response_flags wire_file [finite|cycle] [--expected-response wire_file | --expected-responses framed_file] [--window 1..32] [--capture-responses bounded_output] [--capture-budget-bytes 1..536870912]\n");
        return 2;
    }
    bool finite = false, cycling = false;
    unsigned window = WINDOW;
    bool window_set = false, budget_set = false;
    const char *expected_path = NULL, *expected_list = NULL, *capture_path = NULL;
    for (int i = 6; i < argc; i++) {
        if (!strcmp(argv[i], "finite") && !finite && !cycling) finite = true;
        else if (!strcmp(argv[i], "cycle") && !finite && !cycling) cycling = true;
        else if (!strcmp(argv[i], "--expected-response") && !expected_path && !expected_list && i + 1 < argc)
            expected_path = argv[++i];
        else if (!strcmp(argv[i], "--expected-responses") && !expected_path && !expected_list && i + 1 < argc)
            expected_list = argv[++i];
        else if (!strcmp(argv[i], "--capture-responses") && !capture_path && i + 1 < argc)
            capture_path = argv[++i];
        else if (!strcmp(argv[i], "--capture-budget-bytes") && !budget_set && i + 1 < argc) {
            const char *text = argv[++i];
            if (!*text) fail("invalid capture budget");
            for (const char *p = text; *p; p++)
                if (*p < '0' || *p > '9') fail("invalid capture budget");
            char *budget_end;
            errno = 0;
            unsigned long long requested = strtoull(text, &budget_end, 10);
            if (errno || *budget_end || requested < 1 || requested > CAPTURE_MAX)
                fail("invalid capture budget");
            capture_budget = (size_t)requested;
            budget_set = true;
        } else if (!strcmp(argv[i], "--window") && !window_set && i + 1 < argc) {
            char *window_end;
            long requested = strtol(argv[++i], &window_end, 10);
            if (*window_end || requested < 1 || requested > WINDOW) fail("invalid window");
            window = (unsigned)requested;
            window_set = true;
        } else fail("invalid optional argument");
    }
    if (budget_set && !capture_path) fail("capture budget requires capture output");
    char *end;
    long port = strtol(argv[2], &end, 10);
    if (*end || port < 1 || port > 65535) fail("invalid port");
    double duration = strtod(argv[3], &end);
    if (*end || !(duration > 0 && duration <= 3600)) fail("invalid duration");
    long flags = strtol(argv[4], &end, 10);
    if (*end || flags < 0 || flags > 65535 || !(flags & 0x8000) || (flags & 0x0200))
        fail("invalid expected response flags");
    FILE *file = fopen(argv[5], "rb");
    if (!file) fail("open query");
    unsigned population = load_queries(file, finite || cycling);
    fclose(file);
    size_t expected_size = 0;
    if (expected_path) {
        // Only immutable repeated authority fixtures have a stable wire body.
        // Resolver TTL aging, answer rotation and varying encodings need their
        // own semantic gate rather than this deliberately strict comparison.
        if (finite || cycling) fail("expected response requires one repeated query");
        file = fopen(expected_path, "rb");
        if (!file) fail("open expected response");
        expected_size = fread(expected_reply, 1, MAX_WIRE, file);
        if (ferror(file) || fgetc(file) != EOF || expected_size < 12 ||
            word(expected_reply + 2) != (unsigned)flags) fail("invalid expected response");
        fclose(file);
    }
    if (expected_list) {
        if (!finite && !cycling) fail("expected responses requires finite/cycle queries");
        load_references(expected_list, population, (unsigned)flags);
    }
    if (capture_path) {
        if (!finite && !cycling) fail("capture requires finite/cycle query list");
        // Hard bounded reserve outside timing; overflow fails the entire run.
        capture_stream = malloc(capture_budget);
        if (!capture_stream) fail("allocate response capture");
    }
    size_t sizes[WINDOW], question_ends[WINDOW];
    unsigned input_indices[WINDOW] = {0};
    for (unsigned i = 0; i < window; i++) {
        memcpy(queries[i], inputs[0].wire, inputs[0].size);
        sizes[i] = inputs[0].size;
        question_ends[i] = inputs[0].question_end;
    }

    struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
    if (inet_pton(AF_INET, argv[1], &peer.sin_addr) != 1) fail("invalid IPv4");
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&peer, sizeof(peer))) fail("connect");
    struct mmsghdr received[WINDOW] = {0};
    struct iovec receive_vectors[WINDOW];
    for (unsigned i = 0; i < window; i++) {
        receive_vectors[i] = (struct iovec){replies[i], MAX_WIRE};
        received[i].msg_hdr.msg_iov = &receive_vectors[i];
        received[i].msg_hdr.msg_iovlen = 1;
    }
    bool pending[WINDOW] = {0};
    uint16_t ids[WINDOW];
    double sent_at[WINDOW];
    for (unsigned i = 0; i < window; i++) ids[i] = (uint16_t)i;
    uint64_t sent = 0, completed = 0;
    unsigned active = 0;
    double latency_sum = 0, latency_min = 1e9, latency_max = 0;
    uint64_t next = 0;
    double cpu_started = seconds_clock(CLOCK_PROCESS_CPUTIME_ID);
    struct ClockSnapshot clock_started = clock_snapshot();
    double wall_started = clock_started.wall_ns / 1e9;
    double started = clock_started.monotonic_ns / 1e9, finished = started;
    while (true) {
        double tick = now();
        if (finite && next < population && tick - started >= duration) fail("finite time limit");
        if (finite ? next < population : tick - started < duration) {
            struct mmsghdr outgoing[WINDOW] = {0};
            struct iovec vectors[WINDOW];
            unsigned slots[WINDOW], count = 0;
            for (unsigned i = 0; i < window; i++) {
                if (pending[i]) continue;
                if (finite || cycling) {
                    if (finite && next + count == population) break;
                    input_indices[i] = (unsigned)((next + count) % population);
                    const struct Input *input = &inputs[input_indices[i]];
                    memcpy(queries[i], input->wire, input->size);
                    sizes[i] = input->size;
                    question_ends[i] = input->question_end;
                }
                queries[i][0] = (unsigned char)(ids[i] >> 8);
                queries[i][1] = (unsigned char)ids[i];
                slots[count] = i;
                vectors[count] = (struct iovec){queries[i], sizes[i]};
                outgoing[count].msg_hdr.msg_iov = &vectors[count];
                outgoing[count].msg_hdr.msg_iovlen = 1;
                count++;
            }
            if (count) {
                int n = sendmmsg(fd, outgoing, count, MSG_DONTWAIT);
                if (n < 0 && errno != EAGAIN && errno != EINTR) fail("sendmmsg");
                for (int j = 0; j < n; j++) {
                    unsigned i = slots[j];
                    if (outgoing[j].msg_len != sizes[i]) fail("short UDP send");
                    pending[i] = true;
                    sent_at[i] = tick;
                    sent++;
                    active++;
                    if (finite || cycling) next++;
                }
            }
        } else if (!active) break;

        for (unsigned i = 0; i < window; i++) received[i].msg_hdr.msg_flags = 0;
        int n = recvmmsg(fd, received, window, MSG_DONTWAIT, NULL);
        if (n < 0 && errno != EAGAIN && errno != EINTR) fail("recvmmsg");
        finished = now();
        for (int j = 0; j < n; j++) {
            const unsigned char *reply = replies[j];
            if (received[j].msg_hdr.msg_flags & MSG_TRUNC || received[j].msg_len < 12)
                fail("truncated response");
            unsigned id = word(reply), slot = id % WINDOW;
            if (!pending[slot] || ids[slot] != id) fail("unsolicited or duplicate response");
            if (received[j].msg_len < question_ends[slot] || word(reply + 2) != (unsigned)flags || word(reply + 4) != 1 ||
                memcmp(reply + 12, queries[slot] + 12, question_ends[slot] - 12))
                fail("response flags or question mismatch");
            const struct Input *input = &inputs[input_indices[slot]];
            size_t reference_size = expected_list ? input->expected_size : expected_size;
            const unsigned char *reference = expected_list ? input->expected : expected_reply;
            if (reference_size && (received[j].msg_len != reference_size ||
                memcmp(reply + 2, reference + 2, reference_size - 2)))
                fail("response body mismatch");
            if (capture_path)
                capture_response(input_indices[slot], id, reply, received[j].msg_len,
                                 (uint64_t)((finished - started) * 1e9));
            double latency = finished - sent_at[slot];
            latency_sum += latency;
            if (latency < latency_min) latency_min = latency;
            if (latency > latency_max) latency_max = latency;
            pending[slot] = false;
            ids[slot] = (uint16_t)(ids[slot] + WINDOW);
            active--;
            completed++;
        }
        for (unsigned i = 0; i < window; i++)
            if (pending[i] && finished - sent_at[i] > 2) fail("response timeout");
        if (n <= 0) {
            struct pollfd p = {fd, POLLIN, 0};
            if (poll(&p, 1, 10) < 0 && errno != EINTR) fail("poll");
        }
    }
#ifdef DONNA_CLOCK_TEST_END_DELAY_US
    usleep(DONNA_CLOCK_TEST_END_DELAY_US);
#endif
    struct ClockSnapshot clock_finished = clock_snapshot();
    finished = clock_finished.monotonic_ns / 1e9;
    double wall_finished = clock_finished.wall_ns / 1e9;
    double cpu_seconds = seconds_clock(CLOCK_PROCESS_CPUTIME_ID) - cpu_started;
    close(fd);
    if (!completed || completed != sent || (finite && completed != population)) fail("incomplete load");
    uint64_t capture_bytes = write_capture(capture_path, population, completed, &clock_started);
    printf("{\"queries\":%llu,\"sent\":%llu,\"lost\":0,\"qps\":%.6f,"
           "\"mean_us\":%.6f,\"min_us\":%.6f,\"max_us\":%.6f,\"elapsed_seconds\":%.9f,\"timed_cpu_seconds\":%.9f,\"timed_cpu_percent\":%.6f,\"response_body_verified\":%s,\"outstanding\":%u,\"captured_responses\":%llu,\"capture_bytes\":%llu,\"capture_budget_bytes\":%llu,\"started_unix_seconds\":%.9f,\"ended_unix_seconds\":%.9f,\"started_monotonic_seconds\":%.9f,"
           "\"ended_monotonic_seconds\":%.9f,\"clock_protocol_version\":2,\"clock_start_span_ns\":%llu,\"clock_end_span_ns\":%llu,\"clock_start_uncertainty_ns\":%llu,\"clock_end_uncertainty_ns\":%llu,\"clock_start_attempts\":%u,\"clock_end_attempts\":%u}\n",
           (unsigned long long)completed, (unsigned long long)sent,
           completed / (finished - started), latency_sum / completed * 1e6,
           latency_min * 1e6, latency_max * 1e6, finished - started, cpu_seconds,
           100 * cpu_seconds / (finished - started), (expected_size || expected_list) ? "true" : "false", window, (unsigned long long)(capture_path ? completed : 0),
           (unsigned long long)capture_bytes, (unsigned long long)(capture_path ? capture_budget : 0), wall_started, wall_finished, started, finished,
           (unsigned long long)clock_started.span_ns, (unsigned long long)clock_finished.span_ns,
           (unsigned long long)clock_started.uncertainty_ns, (unsigned long long)clock_finished.uncertainty_ns,
           clock_started.attempts, clock_finished.attempts);
    for (unsigned i = 0; i < population; i++) { free(inputs[i].wire); free(inputs[i].expected); }
    free(capture_stream);
    return 0;
}

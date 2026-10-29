"""Lossless bounded native capture: retain all packet bytes and receive times."""

import hashlib
import io
import math
from pathlib import Path
import struct
import tempfile

MAGIC = b"DNSCAP03"
COMPACT = b"DNSRCP01"
HEADER = 34
LIMIT = 128 * 1024 * 1024
MAX_BUDGET = 512 * 1024 * 1024


def question_end(wire):
    assert len(wire) >= 17 and wire[4:6] == b"\0\1" and not wire[2] & 0x80
    end = 12
    while wire[end]:
        length = wire[end]
        assert length <= 63 and end + length + 1 < len(wire)
        end += length + 1
    end += 5
    assert end <= len(wire)
    return end


def exact(file, size):
    data = file.read(size)
    assert len(data) == size, "truncated capture"
    return data


def capture_header(header, inputs, native):
    assert len(header) == HEADER and header[:8] == MAGIC
    population, wall_ns, mono_ns, completed = struct.unpack_from("!HQQQ", header, 8)
    assert 1 <= population == len(inputs) <= 2048
    assert (
        native["captured_responses"] == completed == native["queries"] == native["sent"]
    )
    budget = native["capture_budget_bytes"]
    assert type(budget) is int and 1 <= budget <= MAX_BUDGET
    assert (
        native["lost"] == 0
        and 0 < completed
        and HEADER <= native["capture_bytes"] <= HEADER + budget
    )
    assert abs(wall_ns / 1e9 - native["started_unix_seconds"]) < 0.000002
    assert abs(mono_ns / 1e9 - native["started_monotonic_seconds"]) < 0.000002
    assert native["clock_protocol_version"] == 2
    uncertainty = 0
    for endpoint in ("start", "end"):
        span = native["clock_" + endpoint + "_span_ns"]
        bound = native["clock_" + endpoint + "_uncertainty_ns"]
        attempts = native["clock_" + endpoint + "_attempts"]
        assert type(span) is int and 0 <= span <= 1_000_000
        assert type(attempts) is int and 1 <= attempts <= 8
        assert type(bound) is int and bound == (span + 1) // 2 + 1000
        uncertainty += bound / 1e9
    elapsed = (
        native["ended_monotonic_seconds"] - native["started_monotonic_seconds"]
    )
    assert abs(elapsed - native["elapsed_seconds"]) < 0.000002
    drift = native["ended_unix_seconds"] - native["started_unix_seconds"] - elapsed
    assert abs(drift) + uncertainty < 0.05, (
        "paired clock offsets disagree beyond 50 ms"
    )
    return population, wall_ns, mono_ns, completed


def validate_records(header, frames, inputs, native):
    population, wall_ns, mono_ns, completed = capture_header(header, inputs, native)
    counts, previous_ns, total = [0] * population, 0, HEADER
    for index, sent_id, response, received_ns in frames:
        assert index < population and 12 <= len(response) <= 65535
        assert (
            previous_ns <= received_ns <= math.ceil(native["elapsed_seconds"] * 1e9) + 2
        )
        previous_ns = received_ns
        query = sent_id.to_bytes(2, "big") + inputs[index][2:]
        end = question_end(query)
        assert response[:2] == query[:2] and response[2] & 0x80
        assert response[4:6] == b"\0\1" and response[12:end] == query[12:end]
        counts[index] += 1
        total += 14 + len(response)
        capture = dict(
            index=index,
            query=query.hex(),
            response=response.hex(),
            received_monotonic_ns=mono_ns + received_ns,
            checked_at=(wall_ns + received_ns) / 1e9,
        )
        # Include the full admitted endpoint-offset budget, not just the
        # sampling bracket. Two endpoints cannot detect an out-and-back
        # clock excursion during the run; this is an explicit model limit.
        capture["clock_uncertainty_seconds"] = (
            0.05
            + (
                native["clock_start_uncertainty_ns"]
                + native["clock_end_uncertainty_ns"]
            )
            / 1e9
        )
        yield capture
    assert sum(counts) == completed
    assert counts == [
        completed // population + (i < completed % population)
        for i in range(population)
    ]
    assert total == native["capture_bytes"]


def raw_frames(file, completed):
    for _ in range(completed):
        index, sent_id, size, elapsed_ns = struct.unpack("!HHHQ", exact(file, 14))
        yield index, sent_id, exact(file, size), elapsed_ns
    assert file.read(1) == b"", "extra capture bytes"


def decode(data, inputs, native):
    file = io.BytesIO(data)
    header = exact(file, HEADER)
    _, _, _, completed = capture_header(header, inputs, native)
    return list(validate_records(header, raw_frames(file, completed), inputs, native))


def compact(source, target, inputs, native):
    """Stream and validate; deduplicate exact bodies, including unmodified TTLs."""
    source, target = Path(source), Path(target)
    bodies, references = [], {}
    original = hashlib.sha256()
    with source.open("rb") as file, tempfile.TemporaryFile() as events:
        header = exact(file, HEADER)
        population, wall, mono, completed = capture_header(header, inputs, native)
        original.update(header)

        def frames():
            for index, sent_id, response, elapsed in raw_frames(file, completed):
                body = response[2:]
                if body not in references:
                    references[body] = len(bodies)
                    bodies.append(body)
                events.write(
                    struct.pack("!HHIQ", index, sent_id, references[body], elapsed)
                )
                original.update(
                    struct.pack("!HHHQ", index, sent_id, len(response), elapsed)
                    + response
                )
                yield index, sent_id, response, elapsed

        for _ in validate_records(header, frames(), inputs, native):
            pass
        with target.open("wb") as output:
            output.write(COMPACT + header + struct.pack("!I", len(bodies)))
            for body in bodies:
                output.write(struct.pack("!H", len(body)) + body)
            events.seek(0)
            while block := events.read(65536):
                output.write(block)
    expected = original.hexdigest()
    rebuilt = hashlib.sha256()
    for block in expanded(target):
        rebuilt.update(block)
    assert rebuilt.hexdigest() == expected, "compaction changed capture bytes"
    return dict(
        raw_sha256=expected,
        compact_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
        raw_bytes=source.stat().st_size,
        compact_bytes=target.stat().st_size,
        packets=completed,
        unique_exact_bodies=len(bodies),
    )


def compact_frames(file):
    assert exact(file, 8) == COMPACT
    header = exact(file, HEADER)
    assert header[:8] == MAGIC, "unsupported capture format"
    completed = struct.unpack_from("!Q", header, 26)[0]
    (count,) = struct.unpack("!I", exact(file, 4))
    assert 1 <= count <= completed
    bodies = [exact(file, struct.unpack("!H", exact(file, 2))[0]) for _ in range(count)]
    assert (
        all(10 <= len(body) <= 65533 for body in bodies) and len(set(bodies)) == count
    )

    def frames():
        for _ in range(completed):
            index, sent_id, reference, elapsed = struct.unpack("!HHIQ", exact(file, 16))
            assert reference < count
            yield (
                index,
                sent_id,
                sent_id.to_bytes(2, "big") + bodies[reference],
                elapsed,
            )
        assert file.read(1) == b"", "extra compact capture bytes"

    return header, frames()


def expanded(path):
    with Path(path).open("rb") as file:
        header, frames = compact_frames(file)
        yield header
        for index, sent_id, response, elapsed in frames:
            yield (
                struct.pack("!HHHQ", index, sent_id, len(response), elapsed) + response
            )


def read_compact(path, inputs, native):
    with Path(path).open("rb") as file:
        header, frames = compact_frames(file)
        yield from validate_records(header, frames, inputs, native)

"""Bounded real Redis script tests using only Python's standard library in Docker."""

from pathlib import Path
import socket
import struct


class RedisError(Exception):
    pass


class Client:
    def __init__(self):
        self.socket = socket.create_connection(("redis", 6379), 3)
        self.socket.settimeout(3)
        self.file = self.socket.makefile("rb")

    def response(self):
        line = self.file.readline()
        assert line.endswith(b"\r\n")
        kind, value = line[:1], line[1:-2]
        if kind == b"-":
            raise RedisError(value.decode())
        if kind == b"+":
            return value
        if kind == b":":
            return int(value)
        if kind == b"$":
            n = int(value)
            if n < 0:
                return None
            assert n < 4 * 1024 * 1024
            data = self.file.read(n)
            assert len(data) == n and self.file.read(2) == b"\r\n"
            return data
        assert kind == b"*"
        n = int(value)
        assert 0 <= n < 65536
        return [self.response() for _ in range(n)]

    def command(self, *args):
        args = [a if isinstance(a, bytes) else str(a).encode() for a in args]
        self.socket.sendall(
            b"*"
            + str(len(args)).encode()
            + b"\r\n"
            + b"".join(
                b"$" + str(len(a)).encode() + b"\r\n" + a + b"\r\n" for a in args
            )
        )
        return self.response()


def wire(owner):
    return (
        b"".join(
            bytes([len(label)]) + label.encode()
            for label in owner.rstrip(".").split(".")
        )
        + b"\0"
    )


def key(category, owner, variant=b""):
    name = wire(owner)
    return (
        bytes([category])
        + struct.pack("!HB", 1, len(name))
        + name
        + struct.pack("!H", len(variant))
        + variant
    )


def item(category, owner, variant=b"", size=64):
    raw = key(category, owner, variant)
    field = b"e:" + raw.hex().encode()
    family = b"f:" + key(category, owner).hex().encode()
    value = (
        struct.pack("!H", len(raw))
        + raw
        + (2**127 - 1).to_bytes(16, "big")
        + struct.pack("!QI", size, size)
        + b"x" * size
    )
    return field, family, value


def check():
    client = Client()
    read = Path("/suite/redis_engine_read.lua").read_text()
    apply = Path("/suite/redis_engine_apply.lua").read_text()
    tests = []

    def keys(ns):
        return "contract:" + ns + ":values", "contract:" + ns + ":fifo"

    def get(
        ns, exact=(), families=(), expected=b"", entries=1024, limit=16 * 1024 * 1024
    ):
        return client.command(
            "EVAL",
            read,
            2,
            *keys(ns),
            expected,
            entries,
            limit,
            len(exact),
            *exact,
            len(families),
            *families,
        )

    def put(ns, expected, mutations, capacity=4096):
        args = []
        for op, (field, family, value) in mutations:
            args.extend([op, field, family, value if op == "P" else b""])
        return client.command(
            "EVAL",
            apply,
            2,
            *keys(ns),
            expected,
            capacity,
            16 * 1024 * 1024,
            len(mutations),
            *args,
        )

    def error(fn):
        try:
            fn()
        except RedisError:
            return
        raise AssertionError("expected server-side rejection")

    values = [item(category, "one.provider.test.") for category in range(1, 7)]
    first = get("six", exact=[v[0] for v in values])
    assert first == [1, b"0", []]
    commit = put("six", b"0", [("P", v) for v in values])
    assert commit == [1, b"1", 0, 0]
    assert put("six", b"0", [("P", values[0])])[0] == 0
    rows = get("six", families=[v[1] for v in values])
    assert len(rows[2]) == 6
    assert get("six", families=[v[1] for v in values])[1] == b"1"
    assert get("six", expected=b"0")[0] == 0
    tests.append(
        "six categories; exact/family reads; no read side effects; stale generation conflict"
    )
    extra = item(1, "one.provider.test.", b"new")
    assert put("six", b"1", [("P", extra)])[1] == b"2"
    assert put("six", b"1", [("A", values[0])])[0] == 0
    assert len(get("six", families=[values[0][1]])[2]) == 2
    error(lambda: get("six", families=[values[0][1]], entries=1))
    assert get("six")[1] == b"2"
    big = item(1, "large.provider.test.", size=2048)
    assert put("six", b"2", [("P", big)])[1] == b"3"
    error(lambda: get("six", exact=[big[0]], limit=1024))
    assert get("six")[1] == b"3"
    tests.append(
        "family phantom conflict; complete entry/byte bounds fail without state change"
    )
    a, b, c = [item(1, name + ".fifo.test.") for name in ("a", "b", "c")]
    assert put("fifo", b"0", [("P", a), ("P", b)], 2)[1] == b"1"
    assert put("fifo", b"1", [("A", a)], 2)[1] == b"2"
    assert put("fifo", b"2", [("P", c)], 2)[2] == 1
    retained = get("fifo", exact=[v[0] for v in (a, b, c)])[2]
    assert {row[0] for row in retained} == {b[0], c[0]}
    assert put("fifo", b"3", [("P", b), ("R", c)], 0)[1] == b"4"
    assert not get("fifo", exact=[v[0] for v in (a, b, c)])[2]
    tests.append(
        "provider FIFO ignores Access; capacity0 removes declined replacement and mandatory removal"
    )
    original = item(1, "original.preflight.test.")
    new = item(1, "new.preflight.test.")
    put("preflight", b"0", [("P", original)])
    client.command("HSET", keys("preflight")[0], b"m:" + original[0], b"f:wrong")
    error(lambda: put("preflight", b"1", [("P", new), ("R", original)]))
    assert client.command("HGET", keys("preflight")[0], "revision") == b"1"
    assert client.command("HGET", keys("preflight")[0], new[0]) is None
    assert client.command("HGET", keys("preflight")[0], original[0]) == original[2]
    tests.append(
        "preflight rejects inconsistent metadata before revision/data mutation"
    )
    for suffix, mutations in (
        ("opcode", [("P", new), ("X", original)]),
        ("payload", [("P", new), ("P", (original[0], original[1], b"x" * 1048577))]),
    ):
        error(lambda: put("invalid-" + suffix, b"0", mutations))
        assert client.command("HLEN", keys("invalid-" + suffix)[0]) == 0
        assert client.command("ZCARD", keys("invalid-" + suffix)[1]) == 0
    client.command("HSET", keys("exhausted")[0], "revision", b"9007199254740991")
    assert get("exhausted")[1] == b"9007199254740991"
    error(lambda: put("exhausted", b"9007199254740991", [("P", new)]))
    assert client.command("HEXISTS", keys("exhausted")[0], new[0]) == 0
    tests.append(
        "invalid operation/oversized later payload/revision overflow preflight before any write"
    )
    for revision in (b"", b"01", b"-1", b"9007199254740992", b"9" * 1000):
        client.command("HSET", keys("corrupt")[0], "revision", revision)
        error(lambda: get("corrupt"))
        error(lambda: put("corrupt", b"0", [("P", original)]))
        assert client.command("HEXISTS", keys("corrupt")[0], original[0]) == 0
    tests.append("malformed/oversized/exhausted revisions fail closed")
    population = [item(1, f"p{n}.population.test.") for n in range(2048)]
    put("population", b"0", [("P", v) for v in population])
    result = get("population", exact=[population[1024][0]])
    assert len(result[2]) == 1 and len(result[2][0][1]) < 1024
    assert client.command("ZCARD", keys("population")[1]) == 2048
    tests.append(
        "2048 unrelated entries; one exact result below1024bytes; no namespace payload serialization"
    )
    return {
        "groups": len(tests),
        "passed": tests,
        "population": 2048,
        "exact_returned_entries": 1,
        "exact_returned_blob_bytes": len(result[2][0][1]),
        "scope": "Opaque provider protocol/Lua only; no DNS authentication or core integration claim.",
    }


if __name__ == "__main__":
    import json

    print(json.dumps(check()), flush=True)

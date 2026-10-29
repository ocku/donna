"""Recheck retained raw DNS packets with Python's standard library only."""

import json
from pathlib import Path
import struct
import sys


def name(data, at, seen=()):
    assert at not in seen and len(seen) < 128
    labels = []
    while data[at]:
        size = data[at]
        if size & 192 == 192:
            target = struct.unpack_from("!H", data, at)[0] & 16383
            tail, _ = name(data, target, seen + (at,))
            return ".".join(labels + [tail.rstrip(".")]) + ".", at + 2
        assert size < 64
        labels.append(data[at + 1 : at + 1 + size].decode("ascii"))
        at += size + 1
    return ".".join(labels) + ".", at + 1


def recheck(rows):
    for row in rows:
        wire = bytes.fromhex(row["wire_hex"])
        _, flags, qd, an, ns, ar = struct.unpack_from("!6H", wire)
        at = 12
        for _ in range(qd):
            _, at = name(wire, at)
            at += 4
        decoded = []
        for section, n in enumerate((an, ns, ar)):
            for _ in range(n):
                owner, at = name(wire, at)
                typ, cl, ttl, size = struct.unpack_from("!HHIH", wire, at)
                at += 10
                if section == 0:
                    assert typ == cl == 1 and size == 4
                    decoded.append(
                        [owner, ttl, ".".join(map(str, wire[at : at + size]))]
                    )
                at += size
        assert at == len(wire) and decoded == row["raw_answer"]


if __name__ == "__main__":
    evidence = json.loads(Path(sys.argv[1]).read_text())
    recheck(evidence["rows"])
    print(json.dumps({"result": "PASS", "raw_rows_verified": len(evidence["rows"])}))

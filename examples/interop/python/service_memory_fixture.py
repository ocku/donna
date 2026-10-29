"""One unsigned zone/positive working set for a later matched service RAM run."""

import argparse
import hashlib
import json
from pathlib import Path
import random
import struct

OWNERS = 4096
KINDS = {"A": 1, "AAAA": 28, "TXT": 16}


def owner(index):
    labels = [f"owner-{index:04d}-" + "x" * (index % 8 * 6)]
    labels += [f"level-{depth}-{index % 13}" for depth in range(index % 4)]
    return ".".join(labels) + ".example.test."


def value(index, kind):
    if kind == "A":
        return f"198.18.{index // 256}.{index % 256}"
    if kind == "AAAA":
        return f"2001:db8::{index + 1:x}"
    return f'"memory-owner-{index:04d}-' + "z" * (index % 4 * 16) + '"'


def query(name, kind):
    labels = [label.encode("ascii") for label in name.rstrip(".").split(".")]
    assert all(0 < len(label) <= 63 for label in labels)
    wire_name = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    assert len(wire_name) <= 255
    return (
        struct.pack("!6H", 0xBEEF, 0, 1, 0, 0, 1)
        + wire_name
        + struct.pack("!2H", KINDS[kind], 1)
        + b"\0"
        + struct.pack("!2HIH", 41, 1232, 0, 0)
    )


def fixture():
    zone = (
        "$ORIGIN example.test.\n$TTL 300\n"
        "@ IN SOA ns.example.test. hostmaster.example.test. 2026102901 3600 600 86400 300\n"
        "@ IN NS ns.example.test.\nns IN A 192.0.2.53\n"
    )
    zone += "".join(
        f"{owner(i)} IN {kind} {value(i, kind)}\n"
        for i in range(OWNERS)
        for kind in KINDS
    )
    rng = random.Random(0x4096768)
    indices = list(range(OWNERS))
    rng.shuffle(indices)
    cases = [
        dict(owner_index=i, name=owner(i), kind=k, expected=value(i, k))
        for i in indices[:256]
        for k in KINDS
    ]
    rng.shuffle(cases)
    packets = [query(case["name"], case["kind"]) for case in cases]
    framed = b"".join(len(packet).to_bytes(2, "big") + packet for packet in packets)
    return zone.encode("ascii"), framed, cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    zone, queries, cases = fixture()
    args.directory.mkdir(parents=True, exist_ok=True)
    (args.directory / "zone.db").write_bytes(zone)
    (args.directory / "queries.framed").write_bytes(queries)
    (args.directory / "manifest.json").write_text(
        json.dumps(
            dict(
                owners=OWNERS,
                data_rrsets=OWNERS * len(KINDS),
                query_population=len(cases),
                zone_sha256=hashlib.sha256(zone).hexdigest(),
                query_pool_sha256=hashlib.sha256(queries).hexdigest(),
                cases=cases,
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()

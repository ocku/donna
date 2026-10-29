"""Deterministic signed-recursion working set and expected immutable data."""

import hashlib
import random

POPULATION = 768
TTL = 300


def prefix(index):
    labels = [f"p{index:04d}" + "x" * (index % 8 * 5)]
    if index % 3:
        labels.append(f"level-{index % 13}")
    return ".".join(labels)


def cases(kind=None):
    rows = []
    for index in range(512):
        part = prefix(index)
        rows.append(
            dict(
                kind="dname",
                name=part + ".old.example.test.",
                rtype="A",
                target=part + ".dest.example.test.",
                value="192.0.2.80",
            )
        )
    for index in range(128):
        name = prefix(index) + ".direct.example.test."
        for rtype, value in (
            ("A", f"198.18.1.{index}"),
            ("AAAA", f"2001:db8:1::{index + 1:x}"),
        ):
            rows.append(
                dict(kind="direct", name=name, rtype=rtype, target=name, value=value)
            )
    random.Random(0xD0512).shuffle(rows)
    assert len(rows) == POPULATION
    return rows if kind is None else [row for row in rows if row["kind"] == kind]


def additions():
    result = [
        "old 300 IN DNAME dest.example.test.",
        "prime.dest 300 IN A 192.0.2.80",
        "expire 5 IN A 192.0.2.81",
        "shortold 5 IN DNAME shortdest.example.test.",
        "expire.shortdest 300 IN A 192.0.2.82",
        "coherence 5 IN A 192.0.2.84",
        "coherence 300 IN AAAA 2001:db8::84",
        'coherence 300 IN TXT "coherence"',
    ]
    for case in cases():
        result.append(f"{case['target']} 300 IN {case['rtype']} {case['value']}")
    return "\n" + "\n".join(result) + "\n"


def request(case, cd=False):
    import dns.flags
    import dns.message

    message = dns.message.make_query(
        case["name"], case["rtype"], want_dnssec=True, payload=1232
    )
    message.id = 0xBEEF
    if cd:
        message.flags |= dns.flags.CD
    return message.to_wire()


def pool(cycles=1, kind=None):
    return [request(case) for _ in range(cycles) for case in cases(kind)]


def frame(packets):
    return b"".join(len(packet).to_bytes(2, "big") + packet for packet in packets)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def preloads(kind=None):
    result = [dict(case, name=case["target"], kind="direct") for case in cases(kind)]
    if kind != "direct":
        result.append(
            dict(
                kind="dname",
                name="prime.old.example.test.",
                rtype="A",
                target="prime.dest.example.test.",
                value="192.0.2.80",
            )
        )
    return result


def expiry_cases():
    return [
        dict(
            kind="direct",
            name="expire.example.test.",
            rtype="A",
            target="expire.example.test.",
            value="192.0.2.81",
        ),
        dict(
            kind="dname",
            name="expire.shortold.example.test.",
            rtype="A",
            target="expire.shortdest.example.test.",
            value="192.0.2.82",
        ),
    ]

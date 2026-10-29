"""One deterministic unsigned authoritative working set; no popularity model."""

import hashlib
import random

POPULATION = 256
TYPES = ("A", "AAAA", "TXT")


def owners():
    for index in range(POPULATION):
        first = f"owner-{index:03d}-" + "x" * (index % 8 * 7)
        labels = [first] + [f"level-{depth}-{index % 13}" for depth in range(index % 4)]
        yield index, ".".join(labels) + ".example.test."


def value(index, kind):
    if kind == "A":
        return f"198.18.0.{index}"
    if kind == "AAAA":
        return f"2001:db8::{index + 1:x}"
    return f'"fixture-{index:03d}-' + "z" * (index % 8 * 24) + '"'


def fixture():
    text = (
        "$ORIGIN example.test.\n$TTL 300\n"
        "@ IN SOA ns.example.test. hostmaster.example.test. 2026102801 3600 600 86400 300\n"
        "@ IN NS ns.example.test.\nns IN A 192.0.2.53\n"
    )
    return text + "".join(
        f"{name} IN {kind} {value(index, kind)}\n"
        for index, name in owners()
        for kind in TYPES
    )


def cases():
    result = [(index, name, kind) for index, name in owners() for kind in TYPES]
    random.Random(0xD0768).shuffle(result)
    return result


def queries():
    import dns.flags
    import dns.message

    result = []
    for _, name, kind in cases():
        query = dns.message.make_query(name, kind, use_edns=0, payload=1232)
        query.flags &= ~dns.flags.RD
        query.id = 0xBEEF
        result.append(query.to_wire())
    return result


def framed(packets):
    return b"".join(len(packet).to_bytes(2, "big") + packet for packet in packets)


def digest(data):
    return hashlib.sha256(data).hexdigest()

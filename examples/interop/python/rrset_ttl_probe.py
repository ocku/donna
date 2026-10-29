"""Raw-wire RFC 2181 TTL matrix; run only in the peers Docker image.

The ordinary dnspython parser normalizes high-bit TTLs and coalesces RRSets,
so use an independent wire walker to retain exactly what each server sent.
"""

import json
import socket
import struct
from urllib.request import urlopen

import dns.flags
import dns.message
import dns.name

AUTHORITY = "http://172.29.55.20:8053/counts"
CASES = {
    "normal": [20, 20],
    "mixed": [20, 6],
    "reversed": [6, 20],
    "high": [0x80000014, 0x80000014],
    "mixedhigh": [20, 0x80000014],
    "zero": [0, 0],
    "duplicate": [20, 20],
    "large": [20] * 39 + [6],
}


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        assert part, "short TCP response"
        result.extend(part)
    return bytes(result)


def exchange(host, port, protocol, name):
    query = dns.message.make_query(name, "A", use_edns=0, payload=1232)
    wire = query.to_wire()
    with socket.socket(
        type=socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    ) as stream:
        stream.settimeout(8)
        stream.connect((host, port))
        if protocol == "tcp":
            stream.sendall(struct.pack("!H", len(wire)) + wire)
            wire = exact(stream, struct.unpack("!H", exact(stream, 2))[0])
        else:
            stream.send(wire)
            wire = stream.recv(65535)
    reply = dns.message.from_wire(wire)
    assert query.is_response(reply), "uncorrelated reply"
    counts = struct.unpack_from("!4H", wire, 4)
    offset = 12
    for _ in range(counts[0]):
        _, consumed = dns.name.from_wire(wire, offset)
        offset += consumed + 4
    answers = []
    for section, count in enumerate(counts[1:]):
        for _ in range(count):
            owner, consumed = dns.name.from_wire(wire, offset)
            offset += consumed
            kind, klass, ttl, size = struct.unpack_from("!HHIH", wire, offset)
            offset += 10
            rdata = wire[offset : offset + size]
            offset += size
            if section == 0:
                assert kind == 1 and klass == 1 and size == 4
                answers.append((owner.to_text(), ttl, socket.inet_ntoa(rdata)))
    assert offset == len(wire), "unparsed response bytes"
    return wire, reply, answers


def count(name):
    with urlopen(AUTHORITY, timeout=3) as response:
        return json.load(response).get(name + "/A", 0)


def expected(kind):
    size = 40 if kind == "large" else 1 if kind == "duplicate" else 2
    return {f"192.0.2.{index + 1}" for index in range(size)}


def check(reply, answers, name, kind):
    assert reply.rcode() == 0
    assert reply.flags & dns.flags.RA and reply.flags & dns.flags.RD
    assert not reply.flags & (dns.flags.AA | dns.flags.AD | dns.flags.TC)
    assert len(answers) == len(expected(kind)), "missing data or duplicate RR"
    assert {address for _, _, address in answers} == expected(kind), "wrong A data"
    assert all(owner == name for owner, _, _ in answers), "wrong answer owner"
    ttls = [ttl for _, ttl, _ in answers]
    assert len(set(ttls)) == 1, "mixed TTLs escaped resolver"
    maximum = min(ttl if ttl < 0x80000000 else 0 for ttl in CASES[kind])
    assert all(0 <= ttl <= maximum for ttl in ttls), "overlong TTL"


def main():
    rows = 0
    faults = 0
    violations = []
    for kind, ttls in CASES.items():
        for protocol in ("udp", "tcp"):
            name = f"ttl-{kind}-direct-{protocol}.example.test."
            wire, reply, answers = exchange("172.29.55.20", 53, protocol, name)
            assert reply.flags & dns.flags.AA and reply.rcode() == 0
            assert [ttl for _, ttl, _ in answers] == ttls, (
                "fixture did not send exact raw TTLs"
            )
            print(
                json.dumps(
                    {
                        "server": "authority",
                        "case": kind,
                        "protocol": protocol,
                        "wire_hex": wire.hex(),
                        "raw_answer": answers,
                    }
                ),
                flush=True,
            )
    for label, host, port in (
        ("donna", "172.29.55.10", 5301),
        ("bind", "172.29.55.11", 53),
    ):
        for protocol in ("udp", "tcp"):
            for kind in CASES:
                name = f"ttl-{kind}-{label}-{protocol}.example.test."
                prior = count(name)
                for stage in ("cold", "repeat"):
                    wire, reply, answers = exchange(host, port, protocol, name)
                    now = count(name)
                    if stage == "cold":
                        assert now > prior, "cold query did not reach authority"
                    if stage == "repeat":
                        cacheable = kind not in ("high", "mixedhigh", "zero")
                        if label == "donna":
                            assert (now == prior) if cacheable else (now > prior), (
                                "incorrect cache lifetime"
                            )
                    print(
                        json.dumps(
                            {
                                "server": label,
                                "case": kind,
                                "protocol": protocol,
                                "stage": stage,
                                "wire_hex": wire.hex(),
                                "raw_answer": answers,
                                "upstream_before": prior,
                                "upstream_after": now,
                            }
                        ),
                        flush=True,
                    )
                    prior = now
                    try:
                        check(reply, answers, name, kind)
                    except AssertionError as error:
                        violations.append(
                            {
                                "server": label,
                                "protocol": protocol,
                                "case": kind,
                                "stage": stage,
                                "error": str(error),
                            }
                        )
                        assert label != "donna", str(error)
                        rows += 1
                        continue
                    # Check the data/TTL gate against independent corruptions.
                    owner, ttl, address = answers[0]
                    for bad in (
                        answers[:-1],
                        answers + answers[:1],
                        [("wrong.example.test.", ttl, address)] + answers[1:],
                        [(owner, 0x80000000, address)] + answers[1:],
                        [(owner, ttl, "192.0.2.250")] + answers[1:],
                    ):
                        try:
                            check(reply, bad, name, kind)
                        except AssertionError:
                            faults += 1
                        else:
                            raise AssertionError("checker accepted injected fault")
                    rows += 1
    print(
        json.dumps(
            {
                "result": "COMPLETE",
                "donna_gate": "PASS",
                "resolver_rows": rows,
                "authority_rows": len(CASES) * 2,
                "checker_faults_rejected": faults,
                "peer_gate_failures": violations,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()

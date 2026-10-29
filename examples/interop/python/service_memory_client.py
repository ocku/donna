"""Validate and warm a fixed authoritative working set; no throughput result."""

import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile

import dns.flags
import dns.message
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from service_memory_fixture import fixture, query


def digest(data):
    return hashlib.sha256(data).hexdigest()


def framed(packets):
    return b"".join(len(p).to_bytes(2, "big") + p for p in packets)


def validate(qwire, rwire, case):
    q, r = dns.message.from_wire(qwire), dns.message.from_wire(rwire)
    assert q.is_response(r) and r.rcode() == 0
    assert r.flags == dns.flags.QR | dns.flags.AA
    assert r.edns == 0 and r.ednsflags == 0 and not r.options
    assert len(rwire) <= 1232 and not r.authority and not r.additional
    assert len(r.answer) == 1
    rr = r.answer[0]
    assert rr.name.to_text() == case["name"] and rr.rdclass == dns.rdataclass.IN
    assert (
        rr.rdtype == dns.rdatatype.from_text(case["kind"])
        and rr.ttl == 300
        and len(rr) == 1
    )
    assert rr[0] == dns.rdata.from_text(dns.rdataclass.IN, rr.rdtype, case["expected"])


def check(record):
    zone, pool, cases = fixture()
    assert record["zone_sha256"] == digest(zone) and record[
        "query_pool_sha256"
    ] == digest(pool)
    assert len(record["packets"]) == len(cases) == 768
    queries, replies = [], []
    for row, case in zip(record["packets"], cases, strict=True):
        q = query(case["name"], case["kind"])
        assert row["query"] == q.hex()
        r = bytes.fromhex(row["response"])
        validate(q, r, case)
        queries.append(q)
        replies.append(r)
    assert record["response_pool_sha256"] == digest(framed(replies))
    return queries, replies


def capture(address):
    zone, pool, cases = fixture()
    packets = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.connect(address)
        peer.settimeout(3)
        for case in cases:
            q = query(case["name"], case["kind"])
            assert peer.send(q) == len(q)
            r = peer.recv(65535)
            validate(q, r, case)
            packets.append(dict(query=q.hex(), response=r.hex()))
    record = dict(
        zone_sha256=digest(zone),
        query_pool_sha256=digest(pool),
        packets=packets,
        response_pool_sha256=digest(
            framed([bytes.fromhex(p["response"]) for p in packets])
        ),
    )
    check(record)
    return record


def warm(address, record, passes):
    queries, replies = check(record)
    rows = []
    with tempfile.TemporaryDirectory(prefix="service-memory-") as temporary:
        root = Path(temporary)
        (root / "q").write_bytes(framed(queries))
        (root / "r").write_bytes(framed(replies))
        for _ in range(passes):
            command = [
                "batched_load",
                address[0],
                str(address[1]),
                "5",
                str(0x8400),
                str(root / "q"),
                "finite",
                "--expected-responses",
                str(root / "r"),
                "--window",
                "32",
            ]
            run = subprocess.run(command, capture_output=True, text=True, timeout=15)
            assert run.returncode == 0, run.stderr
            row = json.loads(run.stdout)
            assert row["queries"] == row["sent"] == 768 and row["lost"] == 0
            assert row["response_body_verified"] is True and row["outstanding"] == 32
            rows.append(dict(native=row, stdout=run.stdout))
    return dict(
        passes=passes,
        responses=passes * 768,
        lost=0,
        exact_bodies=passes * 768,
        response_pool_sha256=record["response_pool_sha256"],
        rows=rows,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("ready", "capture", "warm", "replay"))
    parser.add_argument("--server", default="172.29.57.10:53")
    parser.add_argument(
        "--references", type=Path, default=Path("/suite/references.json")
    )
    parser.add_argument("--passes", type=int, default=40)
    args = parser.parse_args()
    host, port = args.server.rsplit(":", 1)
    address = host, int(port)
    if args.action == "ready":
        with socket.create_connection(address, timeout=3):
            pass
        result = dict(tcp_ready=True, dns_queries=0)
    elif args.action == "capture":
        args.references.write_text(json.dumps(capture(address)) + "\n")
        result = dict(validated=768)
    elif args.action == "replay":
        check(json.loads(args.references.read_text()))
        result = dict(replayed=768, network="none")
    else:
        assert 1 <= args.passes <= 100
        result = warm(address, json.loads(args.references.read_text()), args.passes)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()

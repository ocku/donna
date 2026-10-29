"""Capture, replay and strictly time a finite/mixed authoritative query pool."""

import argparse
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

from diversity_fixture import cases, digest, fixture, framed, queries, value


def validate(query_wire, reply_wire, case):
    query = dns.message.from_wire(query_wire)
    reply = dns.message.from_wire(reply_wire)
    assert query.is_response(reply) and reply.rcode() == 0
    assert reply.flags == dns.flags.QR | dns.flags.AA
    assert reply.edns == 0 and reply.ednsflags == 0 and not reply.options
    assert len(reply_wire) <= 1232 and not reply.authority and not reply.additional
    assert len(reply.answer) == 1
    rr = reply.answer[0]
    index, name, kind = case
    assert rr.name.to_text() == name and rr.rdclass == dns.rdataclass.IN
    assert rr.rdtype == dns.rdatatype.from_text(kind) and rr.ttl == 300 and len(rr) == 1
    assert rr[0] == dns.rdata.from_text(
        dns.rdataclass.IN, rr.rdtype, value(index, kind)
    )
    return reply.flags


def check_reference(record):
    assert record["fixture_sha256"] == digest(fixture().encode())
    expected_queries = queries()
    assert len(record["packets"]) == len(expected_queries) == 768
    replies = []
    flags = set()
    for item, query, case in zip(
        record["packets"], expected_queries, cases(), strict=True
    ):
        assert bytes.fromhex(item["query"]) == query
        reply = bytes.fromhex(item["response"])
        flags.add(validate(query, reply, case))
        replies.append(reply)
    assert len(flags) == 1
    assert record["query_pool_sha256"] == digest(framed(expected_queries))
    assert record["response_pool_sha256"] == digest(framed(replies))
    return expected_queries, replies, flags.pop()


def capture(address):
    packets = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.connect(address)
        peer.settimeout(3)
        for query, case in zip(queries(), cases(), strict=True):
            assert peer.send(query) == len(query)
            reply = peer.recv(65535)
            validate(query, reply, case)
            packets.append({"query": query.hex(), "response": reply.hex()})
    record = dict(
        fixture_sha256=digest(fixture().encode()),
        packets=packets,
        query_pool_sha256=digest(framed([bytes.fromhex(p["query"]) for p in packets])),
        response_pool_sha256=digest(
            framed([bytes.fromhex(p["response"]) for p in packets])
        ),
    )
    check_reference(record)
    return record


def measure(address, record, mode, seconds, strict=True):
    query_wires, replies, flags = check_reference(record)
    with tempfile.TemporaryDirectory(prefix="diversity-load-") as temporary:
        root = Path(temporary)
        (root / "queries").write_bytes(framed(query_wires))
        (root / "responses").write_bytes(framed(replies))
        command = [
            "batched_load",
            address[0],
            str(address[1]),
            str(seconds),
            str(flags),
            str(root / "queries"),
            mode,
        ]
        if strict:
            command += ["--expected-responses", str(root / "responses")]
        run = subprocess.run(
            command, capture_output=True, text=True, timeout=seconds + 10
        )
        assert run.returncode == 0, run.stderr
        row = json.loads(run.stdout)
        assert row["response_body_verified"] == strict and row["lost"] == 0
        assert row["queries"] == row["sent"] and (
            mode != "finite" or row["queries"] == 768
        )
        assert mode != "cycle" or row["queries"] > 768
        row.update(
            input_mode=mode,
            population=768,
            outstanding=32,
            query_pool_sha256=record["query_pool_sha256"],
            response_pool_sha256=record["response_pool_sha256"],
            native_output=run.stdout,
        )
        return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "replay", "finite", "cycle"))
    parser.add_argument("--server", default="127.0.0.1:53")
    parser.add_argument("--references", required=True, type=Path)
    parser.add_argument("--seconds", type=float, default=2)
    parser.add_argument("--without-body", action="store_true")
    args = parser.parse_args()
    host, port = args.server.rsplit(":", 1)
    if args.action == "capture":
        record = capture((host, int(port)))
        args.references.write_text(json.dumps(record) + "\n")
        print(
            json.dumps(
                dict(captured=768, response_pool_sha256=record["response_pool_sha256"])
            ),
            flush=True,
        )
    else:
        record = json.loads(args.references.read_text())
        if args.action == "replay":
            check_reference(record)
            print(json.dumps(dict(replayed=768, network="none")), flush=True)
        else:
            print(
                json.dumps(
                    measure(
                        (host, int(port)),
                        record,
                        args.action,
                        args.seconds,
                        not args.without_body,
                    )
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()

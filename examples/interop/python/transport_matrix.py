"""Unsigned large-RRset UDP recovery and persistent DNS/TCP pipeline checks.

Execute only in the existing Docker peer image; no host DNS dependencies.
"""

import argparse
import itertools
import json
import socket
import struct
import time
from pathlib import Path

import dns.flags
import dns.message
import dns.rdatatype

from dns_packet_layout import layout

PROFILES = (None, 512, 1232, 4096)
CASES = (
    ("www", "A"),
    ("many", "A"),
    ("www", "AAAA"),
    ("alias", "A"),
    ("text", "TXT"),
    ("large", "TXT"),
)


def query(label, kind, payload, identifier):
    result = dns.message.make_query(
        label + ".example.test.",
        kind,
        use_edns=False if payload is None else 0,
        payload=payload or 512,
    )
    result.flags &= ~dns.flags.RD
    result.id = identifier
    return result


def expected(label, kind):
    owner = label + ".example.test."
    if label == "many":
        return {(owner, "A", f"192.0.2.{number}") for number in range(1, 97)}
    if label == "alias":
        return {
            (owner, "CNAME", "www.example.test."),
            ("www.example.test.", "A", "192.0.2.80"),
        }
    if label == "text":
        return {(owner, "TXT", '"hello from an independent DNS client"')}
    if label == "large":
        return {
            (owner, "TXT", '"' + str(number) + ":" + "x" * 100 + '"')
            for number in range(10)
        }
    return {(owner, kind, "192.0.2.80" if kind == "A" else "2001:db8::80")}


def check_reply(request, wire, payload, tcp):
    trailing = None
    try:
        reply = dns.message.from_wire(wire)
    except dns.message.TrailingJunk:
        # RFC2181 §9 says to ignore TC contents and retry with a larger
        # transport. Record strict-decoder sensitivity independently; do not
        # mistake it for proof that the server violated a normative MUST.
        assert not tcp and len(wire) >= 12 and wire[2] & 2
        reply = dns.message.from_wire(wire, ignore_trailing=True)
        trailing = layout(wire)
    assert request.is_response(reply) and reply.rcode() == 0, "wrong question/ID/RCODE"
    assert reply.flags & dns.flags.AA and not reply.flags & dns.flags.RA, (
        "wrong authority flags"
    )
    assert reply.edns == (-1 if payload is None else 0), "EDNS context changed"
    if payload is not None:
        assert not reply.ednsflags & dns.flags.DO
    label = request.question[0].name.labels[0].decode()
    kind = dns.rdatatype.to_text(request.question[0].rdtype)
    want = expected(label, kind)
    values = []
    for rrset in reply.answer:
        assert rrset.rdclass == 1, "wrong answer class"
        values.extend(
            (
                rrset.name.to_text().lower(),
                dns.rdatatype.to_text(rrset.rdtype),
                item.to_text().lower()
                if rrset.rdtype == dns.rdatatype.CNAME
                else item.to_text(),
            )
            for item in rrset
        )
    actual = set(values)
    assert len(actual) == len(values), "duplicate answer data"
    truncated = bool(reply.flags & dns.flags.TC)
    if tcp or not truncated:
        assert not truncated and actual == want, (
            "incomplete or incorrect complete answer"
        )
    else:
        # RFC2181 §9 explicitly permits a partial RRset when TC is set.
        assert actual <= want, "truncated response contains incorrect data"
    if not tcp:
        assert len(wire) <= (payload or 512), "UDP payload exceeds requestor limit"
        if label == "many" and (payload or 512) <= 1232:
            assert truncated, "96 A records cannot fit this UDP limit"
    result = dict(
        bytes=len(wire),
        tc=truncated,
        records=len(actual),
        advertised_payload=reply.payload,
        strict_decoder="TrailingJunk" if trailing else "accepted",
    )
    if trailing:
        result["counted_layout"] = trailing
    return result


def frame(wire):
    return struct.pack("!H", len(wire)) + wire


def read_frame(stream):
    def exact(count):
        data = bytearray()
        while len(data) < count:
            part = stream.recv(min(7, count - len(data)))
            if not part:
                raise EOFError("partial DNS/TCP frame")
            data.extend(part)
        return bytes(data)

    prefix = exact(2)
    size = struct.unpack("!H", prefix)[0]
    assert size >= 12, "invalid DNS/TCP message length"
    body = exact(size)
    return body, prefix + body


def check_rows(rows, allow_errors=False):
    replies = [row for row in rows if "response_wire_hex" in row]
    assert replies, "empty transport matrix"
    servers = {row["server"] for row in replies}
    assert {
        row.get("pipeline_connection") for row in rows if "pipeline_connection" in row
    } == servers
    failed = 0
    for row in replies:
        request = dns.message.from_wire(bytes.fromhex(row["query_wire_hex"]))
        wire = bytes.fromhex(row["response_wire_hex"])
        try:
            observed = check_reply(request, wire, row["payload"], row["phase"] != "udp")
        except Exception as error:
            if not allow_errors:
                raise
            assert (
                row.get("error") == f"{type(error).__name__}: {error}"
                and row["observed"] is None
            )
            failed += 1
        else:
            assert observed == row["observed"] and "error" not in row
        if row["phase"] != "udp":
            assert bytes.fromhex(row["received_frame_hex"]) == frame(wire)
    for server in {row["server"] for row in replies}:
        selected = [row for row in replies if row["server"] == server]
        assert len(selected) == 33
        for profile in PROFILES:
            udp = [
                row
                for row in selected
                if row["phase"] == "udp" and row["payload"] == profile
            ]
            recovered = [
                row
                for row in selected
                if row["phase"] == "tcp-recovery" and row["payload"] == profile
            ]
            assert len(udp) == len(recovered) == 1
            assert udp[0]["query_wire_hex"] == recovered[0]["query_wire_hex"]
            want = (
                query("many", "A", profile, 0x2000 + PROFILES.index(profile))
                .to_wire()
                .hex()
            )
            assert udp[0]["query_wire_hex"] == want
        pipeline = [row for row in selected if row["phase"] == "pipeline"]
        (summary,) = [row for row in rows if row.get("pipeline_connection") == server]
        requests = [
            query(label, kind, profile, 0x3000 + i)
            for i, (profile, (label, kind)) in enumerate(
                itertools.product(PROFILES, CASES)
            )
        ]
        want = {request.id: request.to_wire().hex() for request in requests}
        assert len(pipeline) == len(want) == 24
        got = {
            dns.message.from_wire(bytes.fromhex(row["query_wire_hex"])).id: row[
                "query_wire_hex"
            ]
            for row in pipeline
        }
        assert len(got) == 24 and got == want
        assert (
            sorted(summary["response_ids"])
            == sorted(want)
            == sorted(summary["query_ids"])
        )
        assert summary["response_ids"] == [
            dns.message.from_wire(bytes.fromhex(row["response_wire_hex"])).id
            for row in pipeline
        ]
        writes = [bytes.fromhex(chunk) for chunk in summary["application_writes_hex"]]
        assert len(writes) == 3 and [len(part) for part in writes[:2]] == [1, 7]
        assert b"".join(writes) == b"".join(frame(q.to_wire()) for q in requests)
        (reuse,) = [row for row in selected if row["phase"] == "reuse"]
        assert reuse["query_wire_hex"] == query("www", "A", 512, 0x4000).to_wire().hex()
    return {
        "servers": len({row["server"] for row in replies}),
        "responses": len(replies),
        "truncated_udp": sum(
            row["phase"] == "udp" and bool(row["observed"]) and row["observed"]["tc"]
            for row in replies
        ),
        "tc_trailing_datagrams": sum(
            bool(row["observed"]) and row["observed"]["strict_decoder"] != "accepted"
            for row in replies
        ),
        "failed_reply_checks": failed,
    }


def run_server(server, host, port):
    rows = []

    def keep(phase, request, wire, payload, received=None):
        row = dict(
            server=server,
            phase=phase,
            payload=payload,
            query_wire_hex=request.to_wire().hex(),
            response_wire_hex=wire.hex(),
            observed=None,
        )
        if received is not None:
            row["received_frame_hex"] = received.hex()
        try:
            row["observed"] = check_reply(request, wire, payload, phase != "udp")
        except Exception as error:
            row["error"] = f"{type(error).__name__}: {error}"
        rows.append(row)
        print(json.dumps(row), flush=True)

    for index, payload in enumerate(PROFILES):
        request = query("many", "A", payload, 0x2000 + index)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            stream.connect((host, port))
            stream.send(request.to_wire())
            keep("udp", request, stream.recv(65535), payload)
        with socket.create_connection((host, port), timeout=3) as stream:
            stream.sendall(frame(request.to_wire()))
            wire, received = read_frame(stream)
            keep("tcp-recovery", request, wire, payload, received)
    requests = [
        query(label, kind, payload, 0x3000 + i)
        for i, (payload, (label, kind)) in enumerate(itertools.product(PROFILES, CASES))
    ]
    pending = {
        request.id: (request, payload)
        for request, (payload, _) in zip(requests, itertools.product(PROFILES, CASES))
    }
    combined = b"".join(frame(request.to_wire()) for request in requests)
    writes = (combined[:1], combined[1:8], combined[8:])
    response_ids = []
    with socket.create_connection((host, port), timeout=3) as stream:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for part in writes:
            stream.sendall(part)
            time.sleep(0.005)
        while pending:
            wire, received = read_frame(stream)
            identifier = struct.unpack("!H", wire[:2])[0]
            assert identifier in pending, "unknown or repeated pipelined response ID"
            request, payload = pending.pop(identifier)
            response_ids.append(identifier)
            keep("pipeline", request, wire, payload, received)
        request = query("www", "A", 512, 0x4000)
        stream.sendall(frame(request.to_wire()))
        wire, received = read_frame(stream)
        keep("reuse", request, wire, 512, received)
    rows.append(
        dict(
            pipeline_connection=server,
            query_ids=[q.id for q in requests],
            response_ids=response_ids,
            application_writes_hex=[part.hex() for part in writes],
        )
    )
    print(json.dumps(rows[-1]), flush=True)
    check_rows(rows, allow_errors=True)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--server", action="append", help="LABEL=IPv4:PORT")
    group.add_argument("--replay", type=Path)
    args = parser.parse_args()
    if args.replay:
        rows = [
            json.loads(line)
            for line in args.replay.read_text().splitlines()
            if line.startswith("{")
        ]
        print(json.dumps(check_rows(rows, allow_errors=True)), flush=True)
        return
    rows = []
    failures = []
    for value in args.server:
        server, endpoint = value.split("=", 1)
        host, port = endpoint.rsplit(":", 1)
        try:
            rows.extend(run_server(server, host, int(port)))
        except Exception as error:
            failures.append(server)
            print(
                json.dumps(
                    dict(server=server, failure=f"{type(error).__name__}: {error}")
                ),
                flush=True,
            )
    assert not failures, f"transport matrix failed: {failures}"
    summary = check_rows(rows, allow_errors=True)
    print(json.dumps({"complete": summary}), flush=True)
    assert not summary["failed_reply_checks"], "captured reply checks failed"


if __name__ == "__main__":
    main()

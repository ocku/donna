"""Bounded wire eligibility/error-precedence observations, not a throughput load."""

import argparse
import json
from pathlib import Path
import socket
import struct

import dns.edns
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset


def catalog():
    result = []

    def query(kind="A", version=0, options=None, name="www.example.test."):
        msg = dns.message.make_query(
            name, kind, use_edns=version, payload=1232, options=options
        )
        msg.flags = 0
        return msg

    def add(name, msg, positive=False, expected_rcode=None):
        wire = msg if isinstance(msg, bytes) else msg.to_wire()
        wire = struct.pack("!H", 0x7100 + len(result)) + wire[2:]
        result.append(
            dict(
                case=name,
                query=wire.hex(),
                positive=positive,
                expected_rcode=expected_rcode,
            )
        )

    add("classic", query(version=False), True)
    add("edns", query(), True)
    add("unknown-option", query(options=[dns.edns.GenericOption(65001, b"abc")]), True)
    add("padding", query(options=[dns.edns.GenericOption(12, b"\0" * 8)]), True)
    msg = query()
    msg.ednsflags = dns.flags.DO
    add("dnssec-ok-unsigned", msg, True)
    for name, flag in (
        ("rd", dns.flags.RD),
        ("cd", dns.flags.CD),
        ("tc", dns.flags.TC),
        ("aa", dns.flags.AA),
        ("ra", dns.flags.RA),
    ):
        msg = query()
        msg.flags = flag
        add("query-flag-" + name, msg, name in ("rd", "cd"))
    add("badvers", query(version=1), expected_rcode=16)

    def malformed_option(msg):
        # OPT RDLENGTH covers five bytes; its option length claims four data
        # bytes but only one follows. The enclosing RR is complete.
        wire = msg.to_wire()
        assert wire[-2:] == b"\0\0"
        return wire[:-2] + b"\0\5\xfd\xe9\0\4x"

    add("malformed-option", malformed_option(query()))
    add("badvers-malformed-option", malformed_option(query(version=1)))
    for version in (0, 1):
        wire = query(version=version).to_wire()
        # Duplicate the actual complete OPT RR, and update ARCOUNT.
        duplicate = wire[:10] + b"\0\2" + wire[12:] + wire[-11:]
        add(
            "duplicate-opt-v" + str(version),
            duplicate,
            expected_rcode=1 if version == 0 else None,
        )
    add("trailing-byte", query().to_wire() + b"x")
    for kind in ("AXFR", "IXFR"):
        for version in (0, 1):
            msg = query(kind, version=version, name="example.test.")
            if kind == "IXFR":
                msg.authority.append(
                    dns.rrset.from_text(
                        "example.test.",
                        300,
                        "IN",
                        "SOA",
                        "ns.example.test. hostmaster.example.test. 0 3600 900 1209600 30",
                    )
                )
            add(kind.lower() + "-edns-v" + str(version), msg)
        msg = query(kind, name="example.test.")
        if kind == "IXFR":
            msg.authority.append(
                dns.rrset.from_text(
                    "example.test.",
                    300,
                    "IN",
                    "SOA",
                    "ns.example.test. hostmaster.example.test. 0 3600 900 1209600 30",
                )
            )
        add(kind.lower() + "-malformed-option", malformed_option(msg))
    msg = query()
    msg.question.append(
        dns.rrset.RRset(msg.question[0].name, dns.rdataclass.IN, dns.rdatatype.AAAA)
    )
    add("two-questions-compressed-second", msg, expected_rcode=1)
    wire = query().to_wire()
    add("zero-questions", wire[:4] + b"\0\0" + wire[6:12] + wire[-11:])
    msg = query()
    msg.answer.append(
        dns.rrset.from_text("www.example.test.", 300, "IN", "A", "192.0.2.80")
    )
    add("answer-in-query", msg)
    msg = query(version=False)
    msg.additional.append(
        dns.rrset.from_text(
            "alias.example.test.", 300, "IN", "CNAME", "www.example.test."
        )
    )
    add("compressed-additional-cname", msg)
    add("truncated-additional-cname", msg.to_wire()[:-1])
    msg = query()
    msg.flags = dns.flags.QR
    add("response-bit", msg)
    msg = query()
    msg.set_opcode(2)
    add("status-opcode", msg)
    add("short-header", query().to_wire()[:11])
    assert len({item["case"] for item in result}) == len(result)
    return result


def normalized(wire):
    message = dns.message.from_wire(wire)

    def section(records):
        return sorted(
            (
                rr.name.to_text(),
                rr.rdclass,
                rr.rdtype,
                rr.ttl,
                sorted(item.to_text() for item in rr),
            )
            for rr in records
        )

    return dict(
        flags=message.flags,
        rcode=message.rcode(),
        question=section(message.question),
        answer=section(message.answer),
        authority=section(message.authority),
        additional=section(message.additional),
        edns=message.edns,
        ednsflags=message.ednsflags,
        payload=message.payload,
        options=[(option.otype, option.to_wire().hex()) for option in message.options],
    )


def check_packet(case, wire):
    query = bytes.fromhex(case["query"])
    assert len(wire) >= 12 and wire[:2] == query[:2]
    assert int.from_bytes(wire[2:4], "big") & dns.flags.QR
    result = normalized(wire)
    if case["positive"]:
        request = dns.message.from_wire(query)
        response = dns.message.from_wire(wire)
        assert (
            request.is_response(response)
            and response.rcode() == 0
            and response.flags & dns.flags.AA
        )
        assert not response.flags & (dns.flags.TC | dns.flags.RA)
        assert len(response.answer) == 1
        rr = response.answer[0]
        assert (
            rr.name == request.question[0].name
            and rr.rdclass == 1
            and rr.rdtype == 1
            and rr.ttl == 300
        )
        assert len(rr) == 1 and str(rr[0]) == "192.0.2.80"
    if case["expected_rcode"] is not None:
        assert result["rcode"] == case["expected_rcode"]
    return result


def read_exact(peer, length, received):
    result = b""
    while len(result) < length:
        chunk = peer.recv(length - len(result))
        if not chunk:
            raise EOFError("connection closed before a complete response frame")
        received.extend(chunk)
        result += chunk
    return result


def observe(address, case, protocol):
    wire = bytes.fromhex(case["query"])
    row = dict(case=case["case"], protocol=protocol, query=case["query"])
    received = bytearray()
    with socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    ) as peer:
        peer.settimeout(0.5)
        peer.connect(address)
        try:
            if protocol == "udp":
                assert peer.send(wire) == len(wire)
                response = peer.recv(65535)
            else:
                peer.sendall(len(wire).to_bytes(2, "big") + wire)
                prefix = read_exact(peer, 2, received)
                response = read_exact(peer, int.from_bytes(prefix, "big"), received)
                row["response_frame"] = (prefix + response).hex()
            assert (
                len(response) >= 12 and response[:2] == wire[:2] and response[2] & 0x80
            )
            row.update(
                outcome="reply",
                response=response.hex(),
                normalized=normalized(response),
            )
            try:
                check_packet(case, response)
                row["expectation_failed"] = False
            except AssertionError:
                row["expectation_failed"] = True
        except TimeoutError:
            row["outcome"] = "timeout"
        except (EOFError, ConnectionResetError):
            row["outcome"] = "closed"
    if protocol == "tcp":
        row["received_stream"] = received.hex()
    if row["outcome"] != "reply":
        row["expectation_failed"] = case["expected_rcode"] is not None
    if case["positive"]:
        assert row["outcome"] == "reply", row
    return row


def check_rows(rows, roles):
    cases = {case["case"]: case for case in catalog()}
    assert len(roles) == len(set(roles))
    assert set(roles) in (
        {"current", "knot", "hickory"},
        {"verified", "current", "knot", "hickory"},
    )
    expected = {
        (role, name, protocol)
        for role in roles
        for name in cases
        for protocol in ("udp", "tcp")
    }
    found = {}
    for row in rows:
        key = row["role"], row["case"], row["protocol"]
        assert key in expected and key not in found
        case = cases[row["case"]]
        assert row["query"] == case["query"]
        assert row["outcome"] in ("reply", "timeout", "closed")
        if row["outcome"] == "reply":
            wire = bytes.fromhex(row["response"])
            # JSON changes tuple containers to lists: compare canonical JSON.
            assert (
                len(wire) >= 12
                and wire[:2] == bytes.fromhex(case["query"])[:2]
                and wire[2] & 0x80
            )
            assert json.dumps(row["normalized"], sort_keys=True) == json.dumps(
                normalized(wire), sort_keys=True
            )
            failed = False
            try:
                check_packet(case, wire)
            except AssertionError:
                failed = True
            assert row["expectation_failed"] is failed
            assert not (case["positive"] and failed), "common positive query failed"
            if row["protocol"] == "tcp":
                assert (
                    bytes.fromhex(row["response_frame"])
                    == len(wire).to_bytes(2, "big") + wire
                )
                assert row["received_stream"] == row["response_frame"]
        else:
            assert not case["positive"]
            assert row["expectation_failed"] is (case["expected_rcode"] is not None)
            assert (
                "response" not in row
                and "normalized" not in row
                and "response_frame" not in row
            )
            if row["protocol"] == "tcp":
                bytes.fromhex(row["received_stream"])
        found[key] = row
    assert set(found) == expected
    parity = 0
    for name in cases if "verified" in roles else []:
        for protocol in ("udp", "tcp"):
            before, after = (
                found[(role, name, protocol)] for role in ("verified", "current")
            )
            assert before["outcome"] == after["outcome"], (
                name,
                protocol,
                before,
                after,
            )
            if before["outcome"] == "reply":
                assert before["normalized"] == after["normalized"], (
                    name,
                    protocol,
                    before,
                    after,
                )
            elif protocol == "tcp":
                assert before["received_stream"] == after["received_stream"], (
                    "different partial TCP responses"
                )
            parity += 1
    return dict(
        observations=len(found),
        cases=len(cases),
        compatibility_pairs=parity,
        replies=sum(row["outcome"] == "reply" for row in rows),
        timeouts=sum(row["outcome"] == "timeout" for row in rows),
        closed=sum(row["outcome"] == "closed" for row in rows),
        expectation_failures=[
            (row["role"], row["case"], row["protocol"])
            for row in rows
            if row.get("expectation_failed")
        ],
        scope="First response only for AXFR/IXFR; invalid-case differences between peers are observations, not universal error-precedence requirements",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", action="append", default=[])
    parser.add_argument("--replay", type=Path)
    args = parser.parse_args()
    if args.replay:
        record = json.loads(args.replay.read_text())
        print(json.dumps(check_rows(record["rows"], record["roles"])))
        return
    rows, roles = [], []
    for server in args.server:
        role, endpoint = server.split("=", 1)
        host, port = endpoint.rsplit(":", 1)
        roles.append(role)
        for case in catalog():
            for protocol in ("udp", "tcp"):
                row = dict(role=role, **observe((host, int(port)), case, protocol))
                rows.append(row)
                print(json.dumps(row), flush=True)
    print(json.dumps(dict(complete=check_rows(rows, roles))), flush=True)


if __name__ == "__main__":
    main()

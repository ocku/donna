"""Functional recursive-peer smoke checks; executed only in Docker."""

import argparse
import json
import socket
import struct
import time

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype


def exchange(query, host, protocol):
    wire = query.to_wire()
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as peer:
        peer.settimeout(15)
        peer.connect((host, 53))
        if protocol == "udp":
            peer.send(wire)
            raw = peer.recv(65535)
        else:
            peer.sendall(struct.pack("!H", len(wire)) + wire)

            def read_exact(length):
                data = b""
                while len(data) < length:
                    part = peer.recv(length - len(data))
                    if not part:
                        raise EOFError("short DNS TCP frame")
                    data += part
                return data

            raw = read_exact(struct.unpack("!H", read_exact(2))[0])
    return dns.message.from_wire(raw), raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--bad-ds", action="store_true")
    args = parser.parse_args()
    deadline = time.monotonic() + 12
    while True:
        try:
            with socket.create_connection((args.host, 53), 0.2):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    cases = (
        ("positive", "www.example.test.", "A", 0),
        ("nxdomain", "absent.example.test.", "A", 3),
        ("nodata", "www.example.test.", "AAAA", 0),
    )
    if args.bad_ds:
        cases = (("bad-ds", "www.example.test.", "A", 2),)
    rows = []
    for protocol in ("udp", "tcp"):
        for case, owner, kind, expected_rcode in cases:
            query = dns.message.make_query(owner, kind, want_dnssec=True, payload=1232)
            row = {
                "case": case,
                "protocol": protocol,
                "query_wire_hex": query.to_wire().hex(),
            }
            try:
                reply, raw = exchange(query, args.host, protocol)
                row["response_wire_hex"] = raw.hex()
                assert query.is_response(reply) and reply.rcode() == expected_rcode, (
                    reply.to_text()
                )
                assert reply.flags & dns.flags.RA, reply.to_text()
                assert not reply.flags & (dns.flags.AA | dns.flags.TC), reply.to_text()
                if args.bad_ds:
                    assert not reply.flags & dns.flags.AD and not reply.answer, (
                        reply.to_text()
                    )
                else:
                    assert reply.flags & dns.flags.AD, reply.to_text()
                    if case == "positive":
                        addresses = [
                            r.address
                            for rr in reply.answer
                            if rr.rdtype == dns.rdatatype.A
                            for r in rr
                        ]
                        assert addresses == ["192.0.2.80"], reply.to_text()
                    else:
                        assert not reply.answer, reply.to_text()
                        assert any(
                            rr.rdtype == dns.rdatatype.SOA for rr in reply.authority
                        ), reply.to_text()
                        assert any(
                            rr.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
                            for rr in reply.authority
                        ), reply.to_text()
                    assert any(
                        rr.rdtype == dns.rdatatype.RRSIG
                        for rr in reply.answer + reply.authority
                    ), reply.to_text()
                row["passed"] = True
            except Exception as error:
                row.update(passed=False, error=str(error))
            rows.append(row)
    print(json.dumps(rows))


if __name__ == "__main__":
    main()

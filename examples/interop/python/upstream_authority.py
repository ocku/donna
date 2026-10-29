"""Check wildcard/empty-node semantics against explicitly selected authorities.

Load ../upstream-semantics.db as example.test before invoking this script.
No Docker lifecycle actions or benchmark traffic are performed here.
"""

import argparse
import json
import socket
import struct

from authority_expectations import CASES, validate


def normalized(reply):
    import dns.rdataclass
    import dns.rdatatype

    return {
        "rcode": reply.rcode(),
        "aa": bool(reply.flags & 0x0400),
        "tc": bool(reply.flags & 0x0200),
        "answer": [
            (
                rr.name.to_text().lower(),
                dns.rdatatype.to_text(rr.rdtype),
                item.to_text().lower(),
            )
            for rr in reply.answer
            for item in rr
        ],
        "soas": [
            (
                rr.name.to_text().lower(),
                dns.rdataclass.to_text(rr.rdclass),
                rr.ttl,
                item.minimum,
            )
            for rr in reply.authority
            if rr.rdtype == 6
            for item in rr
        ],
        "nameservers": [
            (
                rr.name.to_text().lower(),
                dns.rdataclass.to_text(rr.rdclass),
                item.to_text().lower(),
            )
            for rr in reply.authority
            if rr.rdtype == 2
            for item in rr
        ],
        "additional": [
            (
                rr.name.to_text().lower(),
                dns.rdataclass.to_text(rr.rdclass),
                dns.rdatatype.to_text(rr.rdtype),
                item.to_text().lower(),
            )
            for rr in reply.additional
            for item in rr
        ],
    }


def endpoint(value):
    label, separator, address = value.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError("expected LABEL=HOST:PORT")
    host, separator, port = address.rpartition(":")
    try:
        if not label or not host or not separator or not 0 < int(port) < 65536:
            raise ValueError()
        return label, host.strip("[]"), int(port)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected LABEL=HOST:PORT with valid port"
        ) from error


def raw_query(query, host, port, protocol):
    """Keep received bytes before a client library can re-encode them."""
    import dns.message

    wire = query.to_wire()
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    family, _, protocol_number, _, address = socket.getaddrinfo(host, port, type=kind)[
        0
    ]
    with socket.socket(family, kind, protocol_number) as stream:
        stream.settimeout(3)
        stream.connect(address)
        if protocol == "udp":
            stream.send(wire)
            wire = stream.recv(65535)
        else:
            stream.sendall(struct.pack("!H", len(wire)) + wire)

            def exact(count):
                result = bytearray()
                while len(result) < count:
                    part = stream.recv(count - len(result))
                    if not part:
                        raise EOFError("short DNS TCP response")
                    result.extend(part)
                return bytes(result)

            wire = exact(struct.unpack("!H", exact(2))[0])
    return dns.message.from_wire(wire), wire


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", action="append", type=endpoint, required=True)
    parser.add_argument(
        "--repeats",
        type=int,
        default=40,
        help="repeat beyond prepared-response thresholds (default 40)",
    )
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("positive repeat count required")
    # Reuse the laboratory's existing dnspython dependency; --help works without it.
    import dns.flags
    import dns.message

    failures = []
    for label, host, port in args.server:
        for protocol in ("udp", "tcp"):
            for case in CASES:
                query = dns.message.make_query(
                    case.name, case.qtype, use_edns=0, payload=1232
                )
                query.flags &= ~dns.flags.RD
                errors = {}
                captures = {}
                for repeat in range(args.repeats):
                    try:
                        reply, wire = raw_query(query, host, port, protocol)
                        observation = {
                            "raw_wire_hex": wire.hex(),
                            "reply": normalized(reply),
                        }
                        if repeat in (0, args.repeats - 1):
                            captures[str(repeat)] = observation
                        assert query.is_response(reply), "uncorrelated response"
                        validate(case, observation["reply"])
                    except Exception as error:
                        key = f"{type(error).__name__}: {error}"
                        if key not in errors:
                            errors[key] = {"count": 0, "first_repeat": repeat}
                        errors[key]["count"] += 1
                row = {
                    "server": label,
                    "protocol": protocol,
                    "name": case.name,
                    "qtype": case.qtype,
                    "checks": args.repeats,
                    "result": "FAIL" if errors else "PASS",
                    "errors": errors,
                    "captures": captures,
                }
                print(json.dumps(row), flush=True)
                if errors:
                    failures.append(
                        {
                            key: row[key]
                            for key in ("server", "protocol", "name", "qtype", "errors")
                        }
                    )
    print(
        json.dumps(
            {
                "result": "FAIL" if failures else "PASS",
                "failures": failures,
                "case_transport_server_rows": len(args.server) * len(CASES) * 2,
            }
        ),
        flush=True,
    )
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

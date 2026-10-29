#!/usr/bin/env python3
"""Replay the authority corpus against explicit UDP/TCP endpoints.

No containers or services are started. Only network execution needs dnspython;
--help, --list and the oracle's unit tests use the Python standard library.
"""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
APEX = "example.test."


@dataclass(frozen=True)
class Case:
    id: str
    name: str
    qtype: str
    rcode: str
    kind: str
    answer: str


def cases():
    return [
        Case(*line.split("\t"))
        for line in HERE.joinpath("authority.tsv").read_text().splitlines()
        if line and not line.startswith("#")
    ]


def records(text):
    """Normalize this corpus's explicit owner/TTL/class/type/RDATA records."""
    result = []

    for record in text.split(";"):
        if not record.strip():
            continue

        owner, ttl, rdclass, kind, data = record.split(maxsplit=4)
        result.append((owner.lower(), int(ttl), rdclass, kind, data.lower()))

    return sorted(result)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(case, reply, rd):
    require(reply["rcode"] == case.rcode, "wrong RCODE")
    require(reply["qr"] and not reply["tc"], "wrong response/truncation flags")
    require(reply["aa"] == (case.kind != "referral"), "wrong AA")
    require(reply["rd"] == rd and not reply["ra"], "wrong RD/RA")
    require(
        sorted(reply["answer"]) == records(case.answer), "wrong answer records or TTLs"
    )

    soas = reply["soas"]
    if case.kind == "negative":
        require(
            soas == [(APEX, "IN", 30, 30)], "wrong negative SOA scope/class/TTL/MINIMUM"
        )
    else:
        require(not soas, "unexpected negative SOA")

    if case.kind == "referral":
        require(
            reply["authority"]
            == records("cut.example.test. 300 IN NS ns.cut.example.test."),
            "wrong delegation NS",
        )
        require(
            records("ns.cut.example.test. 300 IN A 192.0.2.54")[0]
            in reply["additional"],
            "missing in-domain glue",
        )


def normalized(reply):
    import dns.flags
    import dns.rdataclass
    import dns.rdatatype

    def section(rrsets):
        return sorted(
            (
                rr.name.to_text().lower(),
                rr.ttl,
                dns.rdataclass.to_text(rr.rdclass),
                dns.rdatatype.to_text(rr.rdtype),
                item.to_text().lower(),
            )
            for rr in rrsets
            for item in rr
        )

    return {
        "rcode": reply.rcode().name,
        **{
            name: bool(reply.flags & getattr(dns.flags, name.upper()))
            for name in ("qr", "aa", "tc", "rd", "ra")
        },
        "answer": section(reply.answer),
        "authority": section(reply.authority),
        "additional": section(reply.additional),
        "soas": [
            (
                rr.name.to_text().lower(),
                dns.rdataclass.to_text(rr.rdclass),
                rr.ttl,
                item.minimum,
            )
            for rr in reply.authority
            if rr.rdtype == dns.rdatatype.SOA
            for item in rr
        ],
    }


def endpoint(value):
    label, equal, address = value.partition("=")
    host, colon, port = address.rpartition(":")

    try:
        if not label or not equal or not host or not colon or not 0 < int(port) < 65536:
            raise ValueError()
        return label, host.strip("[]"), int(port)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected LABEL=HOST:PORT (IPv6: LABEL=[::1]:PORT)"
        ) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list", action="store_true", help="list cases without DNS dependencies"
    )
    parser.add_argument("--server", type=endpoint, action="append", default=[])
    parser.add_argument("--repeats", type=int, default=40)
    args = parser.parse_args()

    if args.list:
        for case in cases():
            print(f"{case.id:32} {case.name} {case.qtype}")
        return

    if not args.server or args.repeats < 1:
        parser.error("at least one --server and a positive --repeats are required")

    import dns.flags
    import dns.message
    import dns.query

    failures = 0

    for label, host, port in args.server:
        for protocol in ("udp", "tcp"):
            exchange = getattr(dns.query, protocol)
            for case in cases():
                for rd in (False, True):
                    errors = {}
                    for _ in range(args.repeats):
                        try:
                            query = dns.message.make_query(case.name, case.qtype)
                            query.flags = dns.flags.RD if rd else 0

                            # Keep duplicate records visible to the oracle.
                            reply = exchange(
                                query, host, port=port, timeout=3, one_rr_per_rrset=True
                            )
                            require(query.is_response(reply), "uncorrelated response")
                            validate(case, normalized(reply), rd)
                        except Exception as error:
                            key = f"{type(error).__name__}: {error}"
                            errors[key] = errors.get(key, 0) + 1

                    failures += bool(errors)
                    print(
                        json.dumps(
                            dict(
                                server=label,
                                protocol=protocol,
                                case=case.id,
                                rd=rd,
                                checks=args.repeats,
                                errors=errors,
                                result="FAIL" if errors else "PASS",
                            )
                        ),
                        flush=True,
                    )

    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

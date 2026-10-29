"""Gate and time cached recursive service with actual configured DNSSEC anchors."""

import argparse
import json

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from cache_load import measure

SERVERS = [("donna", ("172.29.53.61", 5301)), ("bind", ("172.29.53.60", 53))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("nsec", "nsec3", "nsec3-secure"), required=True
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=2)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument("--verify-bogus", action="store_true")
    parser.add_argument(
        "--workload",
        action="append",
        choices=(
            "positive",
            "negative",
            "nodata",
            "cname",
            "wildcard",
            "cname_negative",
        ),
    )
    args = parser.parse_args()
    if args.repeats < 1 or args.seconds < 1:
        parser.error("repeats and seconds must be positive")
    if args.verify_bogus:
        for server, address in SERVERS:
            for checking_disabled in (False, True):
                query = dns.message.make_query(
                    "www.example.test.", "A", want_dnssec=True, payload=1232
                )
                if checking_disabled:
                    query.flags |= dns.flags.CD
                reply = dns.query.udp(query, address[0], port=address[1], timeout=8)
                assert query.is_response(reply) and reply.flags & dns.flags.RA, (
                    reply.to_text()
                )
                assert not reply.flags & dns.flags.AD, reply.to_text()
                expected = (
                    dns.rcode.NOERROR if checking_disabled else dns.rcode.SERVFAIL
                )
                assert reply.rcode() == expected, (
                    server,
                    checking_disabled,
                    reply.to_text(),
                )
                if checking_disabled:
                    assert any(
                        rr.rdtype == dns.rdatatype.A and rr[0].address == "192.0.2.81"
                        for rr in reply.answer
                    ), reply.to_text()
            print(
                json.dumps(
                    {
                        "verification": "bogus rejected; CD bypass returns tampered data without AD",
                        "server": server,
                        "mode": args.mode,
                    }
                ),
                flush=True,
            )
        return

    cases = [
        ("positive", "www.example.test.", "A", 0),
        ("negative", "missing.example.test.", "A", 3),
        ("nodata", "empty.example.test.", "A", 0),
        ("cname", "alias.example.test.", "A", 0),
        ("wildcard", "m.wild.example.test.", "TXT", 0),
        ("cname_negative", "alias-empty.example.test.", "A", 0),
    ]
    for kind, name, rtype, rcode in cases:
        if args.workload and kind not in args.workload:
            continue
        query = dns.message.make_query(name, rtype, want_dnssec=True, payload=1232)
        prepared = [(query, query.to_wire(), rcode)]
        # RFC 5155 section 9.2 forbids AD when the next-closer proof uses
        # opt-out. Keep this security behavior in the comparison, and also
        # measure a separately signed NSEC3 chain without opt-out.
        expected_ad = not (args.mode == "nsec3" and kind in ("negative", "wildcard"))
        for server, address in SERVERS:
            # Fresh and cached replies must be authenticated. Merely returning
            # signed authoritative records does not satisfy this gate.
            for _ in range(2):
                reply = dns.query.udp(query, address[0], port=address[1], timeout=8)
                assert query.is_response(reply) and reply.rcode() == rcode, (
                    server,
                    reply.to_text(),
                )
                assert (
                    reply.flags & dns.flags.RA
                    and bool(reply.flags & dns.flags.AD) == expected_ad
                ), (server, reply.to_text())
                assert not reply.flags & (dns.flags.AA | dns.flags.TC), (
                    server,
                    reply.to_text(),
                )
                assert reply.edns == 0 and reply.ednsflags & dns.flags.DO, (
                    reply.to_text()
                )
                assert any(
                    rr.rdtype == dns.rdatatype.RRSIG
                    for rr in reply.answer + reply.authority
                ), reply.to_text()
            print(
                json.dumps(
                    {
                        "verification": "fresh and cached DNSSEC policy with signed data",
                        "authenticated_data": expected_ad,
                        "server": server,
                        "mode": args.mode,
                        "workload": kind,
                    }
                ),
                flush=True,
            )
        for repeat in range(args.repeats):
            for server, address in (
                SERVERS if repeat % 2 == 0 else list(reversed(SERVERS))
            ):
                measure(
                    server,
                    address,
                    prepared,
                    kind,
                    repeat,
                    args.seconds,
                    query_format="edns-do",
                    binary_queries=True,
                    load_client=args.load_client,
                )
        # Validate that cached status and proof material survived the timed load.
        for server, address in SERVERS:
            reply = dns.query.udp(query, address[0], port=address[1], timeout=8)
            assert (
                reply.rcode() == rcode
                and bool(reply.flags & dns.flags.AD) == expected_ad
            ), (server, reply.to_text())


if __name__ == "__main__":
    main()

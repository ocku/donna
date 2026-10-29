"""Time the independently verified signed authorities using identical wire queries."""

import argparse
import json

import dns.flags
import dns.message
import dns.query
import dns.rdatatype

from cache_load import measure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("nsec", "nsec3"), required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=2)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument("--cold-population", type=int, default=0)
    args = parser.parse_args()
    if args.repeats < 1 or args.seconds < 1:
        parser.error("repeats and seconds must be positive")
    if not 0 <= args.cold_population <= 2048:
        parser.error("cold population must be 0..2048")
    servers = [("donna", ("172.29.53.14", 5300)), ("bind", ("172.29.53.24", 53))]
    cases = [
        ("positive", "www.example.test.", "A", 0),
        ("negative", "missing.example.test.", "A", 3),
        ("nodata", "empty.example.test.", "A", 0),
        ("wildcard", "m.wild.example.test.", "TXT", 0),
    ]
    for kind, name, rtype, rcode in cases:
        query = dns.message.make_query(name, rtype, want_dnssec=True, payload=1232)
        query.flags &= ~dns.flags.RD
        prepared = [(query, query.to_wire(), rcode)]
        # Full cryptographic and denial checks already passed in signed_probe.
        # Check each timed query's UDP shape and payload limit as well.
        response_flags = {}
        for server, address in servers:
            reply = dns.query.udp(query, address[0], port=address[1], timeout=3)
            assert query.is_response(reply) and reply.rcode() == rcode, reply.to_text()
            assert reply.flags & dns.flags.AA and not reply.flags & dns.flags.TC
            assert reply.edns == 0 and reply.ednsflags & dns.flags.DO
            assert len(reply.to_wire()) <= 1232
            assert any(
                rr.rdtype == dns.rdatatype.RRSIG
                for rr in reply.answer + reply.authority
            )
            response_flags[server] = reply.flags
            if kind in ("positive", "wildcard"):
                assert reply.answer
            else:
                assert not reply.answer and reply.authority
        print(
            json.dumps(
                {
                    "signed_mode": args.mode,
                    "workload": kind,
                    "verification": "passed",
                    "edns_payload": 1232,
                }
            ),
            flush=True,
        )
        for repeat in range(args.repeats):
            if args.cold_population:
                prepared = []
                for i in range(args.cold_population):
                    owner = (
                        f"fresh-{repeat}-{i}.wild.example.test."
                        if kind == "wildcard"
                        else f"fresh-{kind}-{repeat}-{i}.example.test."
                    )
                    fresh = dns.message.make_query(
                        owner, rtype, want_dnssec=True, payload=1232
                    )
                    fresh.flags &= ~dns.flags.RD
                    prepared.append((fresh, fresh.to_wire(), rcode))
            for server, address in (
                servers if repeat % 2 == 0 else list(reversed(servers))
            ):
                measure(
                    server,
                    address,
                    prepared,
                    kind,
                    repeat,
                    30 if args.cold_population else args.seconds,
                    query_format="edns-do",
                    binary_queries=True,
                    load_client=args.load_client,
                    max_runs=1 if args.cold_population else None,
                    expected_response_flags=response_flags[server]
                    if args.cold_population
                    else None,
                )


if __name__ == "__main__":
    main()

"""Measure a fully cold first query, then a finite list of cold owners."""

import argparse
import asyncio
import json
import socket
import time

import dns.message
import dns.query

from cache_network import batch, queries
from cache_load import measure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", choices=("donna", "bind"), required=True)
    parser.add_argument(
        "--workload", choices=("positive", "negative", "cname"), required=True
    )
    parser.add_argument("--repeat", type=int, required=True)
    parser.add_argument("--population", type=int, default=1024)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    args = parser.parse_args()
    if not 1 <= args.population <= 2048:
        parser.error("population must be 1..2048")
    address = ("172.29.53.51", 5301) if args.server == "donna" else ("172.29.53.50", 53)
    deadline = time.monotonic() + 10
    # Opening a TCP connection establishes listener readiness without a DNS
    # exchange or populating any resolution/delegation cache.
    while True:
        try:
            with socket.create_connection(address, timeout=0.2):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)
    names = {
        "positive": ("first-cold.wild.example.test.", "TXT", 0),
        "negative": ("first-cold-missing.example.test.", "A", 3),
        "cname": ("alias.example.test.", "A", 0),
    }
    name, rtype, rcode = names[args.workload]
    query = dns.message.make_query(name, rtype, use_edns=0, payload=1232)
    started = time.perf_counter_ns()
    reply = dns.query.udp(query, address[0], port=address[1], timeout=5)
    elapsed = (time.perf_counter_ns() - started) / 1000
    assert query.is_response(reply) and reply.rcode() == rcode, reply.to_text()
    assert reply.flags & dns.flags.RA and not reply.flags & dns.flags.TC
    assert bool(reply.answer) == (rcode == 0)
    if rcode == 3:
        assert reply.authority
    print(
        json.dumps(
            {
                "server": args.server,
                "workload": args.workload,
                "repeat": args.repeat,
                "phase": "fully_cold_first_query",
                "client": "dnspython",
                "latency_us": elapsed,
                "query_format": "edns",
                "edns_payload": 1232,
            }
        ),
        flush=True,
    )
    if args.workload == "cname":
        return  # This fixture has one alias; repeating it would be a warm hit.
    prepared = queries(args.workload, args.population, "edns")
    assert len({str(q.question[0].name) for q, _, _ in prepared}) == args.population
    assert all(q.question[0].name != query.question[0].name for q, _, _ in prepared)
    print(
        json.dumps(
            {
                "phase": "cold_owners_warm_delegations",
                "server": args.server,
                "workload": args.workload,
                "repeat": args.repeat,
            }
        ),
        flush=True,
    )
    measure(
        args.server,
        address,
        prepared,
        args.workload,
        args.repeat,
        30,
        query_format="edns",
        binary_queries=True,
        max_runs=1,
        load_client=args.load_client,
        expected_response_flags=reply.flags,
    )
    # Verify every owner outside timing, after its sole native query.
    asyncio.run(batch(address, prepared, len(prepared), 32))
    print(
        json.dumps(
            {
                "verification": "all_owners_passed",
                "server": args.server,
                "workload": args.workload,
                "repeat": args.repeat,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()

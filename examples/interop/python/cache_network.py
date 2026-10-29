"""Compare cached UDP replies from Donna and BIND using the same client.

Run in the isolated interop network via cache.py. Both servers recurse through
the unsigned lab hierarchy. This measures client-observed network behavior,
not raw cache operations or production DNSSEC performance.
"""

import argparse
import asyncio
import json
import socket
import statistics
import time

import dns.flags
import dns.message
import dns.rcode


def queries(kind, population, query_format="classic"):
    result = []
    for index in range(population):
        if kind == "positive":
            name, rtype, rcode = (
                f"cache-{index}.wild.example.test.",
                "TXT",
                dns.rcode.NOERROR,
            )
        elif kind == "negative":
            name, rtype, rcode = (
                f"cache-missing-{index}.example.test.",
                "A",
                dns.rcode.NXDOMAIN,
            )
        else:
            name, rtype, rcode = "alias.example.test.", "A", dns.rcode.NOERROR
        query = dns.message.make_query(
            name,
            rtype,
            use_edns=-1 if query_format == "classic" else 0,
            want_dnssec=query_format == "edns-do",
        )
        result.append((query, query.to_wire(), rcode))
    return result


async def batch(address, prepared, count, concurrency):
    loop = asyncio.get_running_loop()
    samples = []

    async def worker(worker_id):
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.setblocking(False)
        connection.connect(address)
        try:
            for index in range(worker_id, count, concurrency):
                query, wire, expected_rcode = prepared[index % len(prepared)]
                started = time.perf_counter_ns()
                await loop.sock_sendall(connection, wire)
                response_wire = await asyncio.wait_for(
                    loop.sock_recv(connection, 65535), 5
                )
                elapsed = time.perf_counter_ns() - started
                # Validate outside the timed interval, identically for both servers.
                response = dns.message.from_wire(response_wire)
                assert response.id == query.id and response.question == query.question
                assert response.rcode() == expected_rcode, response.to_text()
                assert (
                    response.flags & dns.flags.RA and not response.flags & dns.flags.TC
                )
                if query.edns >= 0:
                    assert response.edns == 0
                    assert bool(response.ednsflags & dns.flags.DO) == bool(
                        query.ednsflags & dns.flags.DO
                    )
                if expected_rcode == dns.rcode.NXDOMAIN:
                    assert not response.answer and response.authority
                else:
                    assert response.answer
                samples.append(elapsed / 1000)
        finally:
            connection.close()

    started = time.perf_counter()
    await asyncio.gather(*(worker(index) for index in range(concurrency)))
    elapsed = time.perf_counter() - started
    samples.sort()
    return {
        "queries": count,
        "concurrency": concurrency,
        "qps": round(count / elapsed),
        "median_us": round(statistics.median(samples), 2),
        "p95_us": round(samples[len(samples) * 95 // 100], 2),
    }


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--population", type=int, default=1024)
    parser.add_argument("--queries", type=int, default=10000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--donna-host", default="172.29.53.51")
    parser.add_argument("--server", choices=("donna", "bind"))
    parser.add_argument("--workload", choices=("positive", "negative", "cname"))
    parser.add_argument("--repeat-offset", type=int, default=0)
    parser.add_argument("--source-port", type=int)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument(
        "--query-format", choices=("classic", "edns", "edns-do"), default="classic"
    )
    parser.add_argument(
        "--load-seconds",
        type=int,
        default=0,
        help="use native dnsperf load client for this duration instead of Python timing",
    )
    args = parser.parse_args()
    if (
        not 1 <= args.population <= 2048
        or args.queries < 1
        or args.repeats < 1
        or args.load_seconds < 0
    ):
        parser.error("population must be 1..2048; queries and repeats must be positive")
    if args.load_client == "batched" and (
        args.load_seconds <= 0 or args.source_port is not None
    ):
        parser.error(
            "batched load needs positive --load-seconds and no fixed source port"
        )
    if args.source_port is not None and not 1024 <= args.source_port <= 65535:
        parser.error("source port must be 1024..65535")
    servers = [("donna", (args.donna_host, 5301)), ("bind", ("172.29.53.50", 53))]
    if args.server:
        servers = [item for item in servers if item[0] == args.server]
    for kind in (
        (args.workload,) if args.workload else ("positive", "negative", "cname")
    ):
        prepared = queries(
            kind, args.population if kind != "cname" else 1, args.query_format
        )
        for concurrency in (32,) if args.load_seconds else (1, 32):
            for repeat in range(args.repeats):
                # Alternate server order to reduce bias from temperature and host load.
                reported_repeat = repeat + args.repeat_offset
                order = servers if reported_repeat % 2 == 0 else list(reversed(servers))
                for name, address in order:
                    await batch(
                        address, prepared, len(prepared), min(32, len(prepared))
                    )
                    if args.load_seconds:
                        from cache_load import measure

                        measure(
                            name,
                            address,
                            prepared,
                            kind,
                            reported_repeat,
                            args.load_seconds,
                            args.source_port,
                            args.query_format,
                            load_client=args.load_client,
                        )
                        if args.load_client == "batched":
                            await batch(
                                address, prepared, len(prepared), min(32, len(prepared))
                            )
                        continue
                    result = await batch(address, prepared, args.queries, concurrency)
                    print(
                        json.dumps(
                            {
                                "server": name,
                                "workload": kind,
                                "repeat": repeat,
                                "population": len(prepared),
                                "query_format": args.query_format,
                                **result,
                            }
                        ),
                        flush=True,
                    )


if __name__ == "__main__":
    asyncio.run(main())

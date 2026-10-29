"""Cold first-query and finite owner batches with a root-only DNSSEC anchor."""

import argparse
import asyncio
import json
import socket
import time

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from cache_load import measure


def verify(query, reply, rcode, nodata=False):
    assert query.is_response(reply) and reply.rcode() == rcode, reply.to_text()
    assert reply.flags & dns.flags.RA and reply.flags & dns.flags.AD, reply.to_text()
    assert not reply.flags & (dns.flags.AA | dns.flags.TC), reply.to_text()
    assert reply.edns == 0 and reply.ednsflags & dns.flags.DO, reply.to_text()
    assert bool(reply.answer) == (rcode == dns.rcode.NOERROR and not nodata), (
        reply.to_text()
    )
    assert any(
        rr.rdtype == dns.rdatatype.RRSIG for rr in reply.answer + reply.authority
    ), reply.to_text()


async def verify_all(address, prepared, nodata):
    # Every owner has already had its sole timed native query. Verification is
    # outside timing and never prewarms a measured owner.
    async def worker(index):
        import dns.asyncquery

        for query, _, rcode in prepared[index::32]:
            reply = await dns.asyncquery.udp(
                query, address[0], port=address[1], timeout=8
            )
            verify(query, reply, rcode, nodata)

    await asyncio.gather(*(worker(i) for i in range(min(32, len(prepared)))))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", choices=("donna", "bind"), required=True)
    parser.add_argument("--mode", choices=("nsec", "nsec3"), required=True)
    parser.add_argument(
        "--workload", choices=("positive", "negative", "nodata"), default="positive"
    )
    parser.add_argument("--repeat", type=int, default=0)
    parser.add_argument("--population", type=int, default=1024)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument("--verify-bad-ds", action="store_true")
    parser.add_argument("--verify-chain", action="store_true")
    parser.add_argument(
        "--cold-chain-batch",
        action="store_true",
        help="send the finite owner batch before any control DNS query",
    )
    parser.add_argument(
        "--expected-response-flags",
        type=int,
        help="flags observed on a separate, discarded resolver instance",
    )
    args = parser.parse_args()
    if not 1 <= args.population <= 2048:
        parser.error("population must be 1..2048")
    if args.cold_chain_batch and (
        args.verify_chain or args.verify_bad_ds or args.expected_response_flags is None
    ):
        parser.error("cold-chain batch requires flags from a separate control instance")
    address = ("172.29.53.74", 5301) if args.server == "donna" else ("172.29.53.73", 53)
    deadline = time.monotonic() + 10
    while True:
        try:
            with socket.create_connection(address, timeout=0.2):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)
    if args.verify_bad_ds:
        for cd in (False, True):
            query = dns.message.make_query(
                "www.example.test.", "A", want_dnssec=True, payload=1232
            )
            if cd:
                query.flags |= dns.flags.CD
            reply = dns.query.udp(query, address[0], port=address[1], timeout=10)
            assert query.is_response(reply) and reply.flags & dns.flags.RA, (
                reply.to_text()
            )
            assert not reply.flags & dns.flags.AD, reply.to_text()
            assert reply.rcode() == (dns.rcode.NOERROR if cd else dns.rcode.SERVFAIL), (
                reply.to_text()
            )
            if cd:
                assert any(
                    rr.rdtype == dns.rdatatype.A and rr[0].address == "192.0.2.80"
                    for rr in reply.answer
                ), reply.to_text()
        print(
            json.dumps(
                {
                    "verification": "incorrect signed child DS rejected; CD returns data without AD",
                    "server": args.server,
                    "mode": args.mode,
                }
            ),
            flush=True,
        )
        return

    if args.cold_chain_batch:
        control_flags = args.expected_response_flags
    else:
        query = dns.message.make_query(
            "www.example.test.", "A", want_dnssec=True, payload=1232
        )
        started = time.perf_counter_ns()
        reply = dns.query.udp(query, address[0], port=address[1], timeout=10)
        elapsed = (time.perf_counter_ns() - started) / 1000
        verify(query, reply, dns.rcode.NOERROR)
        if args.verify_chain:
            print(
                json.dumps(
                    {
                        "verification": "root-only anchor authenticates leaf answer",
                        "server": args.server,
                        "mode": args.mode,
                        "response_flags": reply.flags,
                    }
                ),
                flush=True,
            )
            return
        print(
            json.dumps(
                {
                    "server": args.server,
                    "mode": args.mode,
                    "workload": args.workload,
                    "repeat": args.repeat,
                    "phase": "first_client_query_root_anchor",
                    "latency_us": elapsed,
                    "scope": "fresh validating resolver; normal startup/root priming retained",
                }
            ),
            flush=True,
        )
        # This separate positive control warmed the chain, never a measured owner.
        control_flags = reply.flags
    prepared = []
    for index in range(args.population):
        name, rtype, rcode = (
            (f"n-{index:04d}-b.example.test.", "A", dns.rcode.NXDOMAIN)
            if args.workload == "negative"
            else (
                f"host-{index:04d}.example.test.",
                "AAAA" if args.workload == "nodata" else "A",
                dns.rcode.NOERROR,
            )
        )
        query = dns.message.make_query(name, rtype, want_dnssec=True, payload=1232)
        prepared.append((query, query.to_wire(), rcode))
    expected_flags = (control_flags & ~0x000F) | prepared[0][2]
    assert expected_flags & (dns.flags.QR | dns.flags.RA | dns.flags.AD) == (
        dns.flags.QR | dns.flags.RA | dns.flags.AD
    )
    assert not expected_flags & (dns.flags.AA | dns.flags.TC)
    measure(
        args.server,
        address,
        prepared,
        args.workload,
        args.repeat,
        30,
        query_format="edns-do",
        binary_queries=True,
        max_runs=1,
        load_client=args.load_client,
        expected_response_flags=expected_flags,
    )
    asyncio.run(verify_all(address, prepared, args.workload == "nodata"))
    print(
        json.dumps(
            {
                "verification": "all owners authenticated after sole timed query",
                "server": args.server,
                "mode": args.mode,
                "workload": args.workload,
                "repeat": args.repeat,
                "population": args.population,
                "scope": (
                    "fresh resolver finite batch; no DNS control query; normal startup/root priming retained"
                    if args.cold_chain_batch
                    else "cold client owners; delegation/DNSKEY caches warmed by separate first query; authenticated denial proofs may be reused"
                ),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()

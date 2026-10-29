"""Matched authoritative queries for independently verified Docker peers."""

import argparse
import hashlib
import json
import socket
import time

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from cache_load import measure

SERVERS = [
    ("donna-verified", ("172.29.54.10", 5300)),
    ("donna-current", ("172.29.54.11", 5300)),
    ("bind", ("172.29.54.20", 53)),
    ("knot", ("172.29.54.30", 53)),
    ("nsd", ("172.29.54.40", 53)),
]
OPTIONAL_SERVERS = [("hickory", ("172.29.54.50", 53))]
CASES = [
    ("positive", "www.example.test.", "A", 0),
    ("negative", "missing.example.test.", "A", 3),
    ("nodata", "empty.example.test.", "A", 0),
    ("wildcard", "m.wild.example.test.", "TXT", 0),
    ("wildcard-nodata", "m.wild.example.test.", "A", 0),
]


def query_for(mode, name, rtype):
    query = dns.message.make_query(
        name, rtype, use_edns=0, want_dnssec=mode != "unsigned", payload=1232
    )
    query.flags &= ~dns.flags.RD
    query.id = 0xBEEF
    return query


def received_packet(query, address):
    """Keep the peer's actual encoding; reserialization changes compression."""
    wire = query.to_wire()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(3)
        peer.connect(address)
        assert peer.send(wire) == len(wire)
        received = peer.recv(65535)
    assert len(received) <= 1232
    return dns.message.from_wire(received), received


def shape(query, reply, kind, rcode):
    assert query.is_response(reply) and reply.rcode() == rcode, reply.to_text()
    assert reply.flags & dns.flags.AA and not reply.flags & (
        dns.flags.RA | dns.flags.AD | dns.flags.CD | dns.flags.TC
    )
    assert reply.edns == 0 and bool(reply.ednsflags & dns.flags.DO) == bool(
        query.ednsflags & dns.flags.DO
    )
    assert len(reply.to_wire()) <= 1232
    # The fixture has one data RRset. A correctly signed RRset for a different
    # owner (or an extra answer) is not an answer to this benchmark question.
    data = [rr for rr in reply.answer if rr.rdtype != dns.rdatatype.RRSIG]
    if kind == "positive":
        assert len(data) == 1
        rr = data[0]
        assert rr.name == query.question[0].name and rr.rdclass == dns.rdataclass.IN
        assert (
            rr.rdtype == dns.rdatatype.A and len(rr) == 1 and str(rr[0]) == "192.0.2.80"
        )
    elif kind == "wildcard":
        assert len(data) == 1
        rr = data[0]
        assert rr.name == query.question[0].name and rr.rdclass == dns.rdataclass.IN
        assert (
            rr.rdtype == dns.rdatatype.TXT
            and len(rr) == 1
            and rr[0].strings == (b"wildcard",)
        )
    else:
        assert not reply.answer
        soas = [rr for rr in reply.authority if rr.rdtype == dns.rdatatype.SOA]
        assert len(soas) == 1
        soa = soas[0]
        assert soa.name == dns.name.from_text("example.test.")
        assert soa.rdclass == dns.rdataclass.IN and len(soa) == 1
        assert soa.ttl == 30 and soa[0].minimum == 30


def verify_response(mode, query, response, kind, rcode, keys, now=None):
    from signed_probe import (
        APEX,
        covers,
        nsec3_covers,
        nsec3_matches,
        verify_denial,
        verify_signatures,
        witnesses,
    )

    shape(query, response, kind, rcode)
    if keys is not None:
        verify_signatures(response, keys, now=now)
        qname = query.question[0].name
        if kind == "nodata":
            verify_denial(response, mode, qname, "empty-nodata")
        elif kind == "wildcard-nodata":
            verify_denial(response, mode, qname, kind)
        elif kind == "negative":
            wildcard = dns.name.from_text("*.example.test.")
            if mode == "nsec":
                proofs = witnesses(response, dns.rdatatype.NSEC)
                assert all(
                    any(covers(owner, item.next, candidate) for owner, item in proofs)
                    for candidate in (qname, wildcard)
                )
            else:
                proofs = witnesses(response, dns.rdatatype.NSEC3)
                assert nsec3_matches(proofs, APEX)
                assert nsec3_covers(proofs, qname) and nsec3_covers(proofs, wildcard)
        elif kind == "wildcard":
            if mode == "nsec":
                assert any(
                    covers(owner, item.next, qname)
                    for owner, item in witnesses(response, dns.rdatatype.NSEC)
                )
            else:
                proofs = witnesses(response, dns.rdatatype.NSEC3)
                # RFC 5155 sections 7.2.6/8.8: the authenticated
                # expanded wildcard establishes its closest encloser.
                # Only the next-closer cover is mandatory here.
                assert nsec3_covers(proofs, qname)


def verify(mode, cases=None):
    import dns.zone
    from signed_probe import APEX

    zone = dns.zone.from_file("/work/active.db", origin=APEX, relativize=False)
    keys = (
        {APEX: zone.get_rdataset(APEX, dns.rdatatype.DNSKEY)}
        if mode != "unsigned"
        else None
    )
    for server, address in SERVERS:
        for kind, name, rtype, rcode in CASES:
            if cases and kind not in cases:
                continue
            query = query_for(mode, name, rtype)
            # Exercise the current prototype beyond its preparation gate before
            # independent checks. This control traffic is outside timing.
            captures = {}
            for _ in range(40):
                response, received = received_packet(query, address)
                checked_at = time.time()
                verify_response(
                    mode, query, response, kind, rcode, keys, now=checked_at
                )
                captured = captures.setdefault(
                    received.hex(),
                    dict(
                        response_wire_hex=received.hex(),
                        checked_at=checked_at,
                        last_checked_at=checked_at,
                        occurrences=0,
                    ),
                )
                captured["occurrences"] += 1
                captured["last_checked_at"] = checked_at
            print(
                json.dumps(
                    {
                        "verification": "independent signature/mandatory-witness/shape checks"
                        if keys
                        else "unsigned shape/data checks",
                        "server": server,
                        "mode": mode,
                        "workload": kind,
                        "response_bytes": len(response.to_wire()),
                        "response_flags": response.flags,
                        "authority_types": [rr.rdtype for rr in response.authority],
                        "verified_replies": 40,
                        "captures": list(captures.values()),
                        "query_wire_hex": query.to_wire().hex(),
                    }
                ),
                flush=True,
            )


def main():
    global SERVERS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("unsigned", "nsec", "nsec3"), required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument(
        "--load-client", choices=("batched", "dnsperf"), default="batched"
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=2)
    parser.add_argument("--cpu-handshake", action="store_true")
    parser.add_argument(
        "--verify-wire",
        action="store_true",
        help="check every timed immutable authority response against its independently validated preflight",
    )
    parser.add_argument("--cases", nargs="+", choices=[c[0] for c in CASES])
    parser.add_argument(
        "--servers", nargs="+", choices=[name for name, _ in SERVERS + OPTIONAL_SERVERS]
    )
    args = parser.parse_args()
    if args.servers:
        available = dict(SERVERS + OPTIONAL_SERVERS)
        SERVERS = [(name, available[name]) for name in args.servers]
    if args.verify:
        verify(args.mode, args.cases)
        return
    assert args.repeats > 0 and args.seconds > 0
    if args.verify_wire and args.load_client != "batched":
        parser.error("--verify-wire requires the batched client")
    import dns.zone

    apex = dns.name.from_text("example.test.")
    zone = dns.zone.from_file("/work/active.db", origin=apex, relativize=False)
    keys = (
        {apex: zone.get_rdataset(apex, dns.rdatatype.DNSKEY)}
        if args.mode != "unsigned"
        else None
    )
    for kind, name, rtype, rcode in CASES:
        if args.cases and kind not in args.cases:
            continue
        query = query_for(args.mode, name, rtype)
        wire = query.to_wire()
        for repeat in range(args.repeats):
            order = SERVERS[repeat % len(SERVERS) :] + SERVERS[: repeat % len(SERVERS)]
            if repeat % 2:
                order = list(reversed(order))
            for server, address in order:
                reply, received = received_packet(query, address)
                checked_at = time.time()
                if args.verify_wire:
                    verify_response(
                        args.mode, query, reply, kind, rcode, keys, now=checked_at
                    )
                else:
                    shape(query, reply, kind, rcode)
                print(
                    json.dumps(
                        {
                            "mode": args.mode,
                            "server": server,
                            "workload": kind,
                            "repeat": repeat,
                            "query_sha256": hashlib.sha256(wire).hexdigest(),
                            "query_wire_hex": wire.hex(),
                            "checked_at": checked_at,
                            "expected_response_wire_hex": received.hex(),
                            "response_flags": reply.flags,
                            "preflight_response_bytes": len(reply.to_wire()),
                        }
                    ),
                    flush=True,
                )
                if args.cpu_handshake and input() != "continue":
                    raise RuntimeError("missing CPU-trial start acknowledgement")
                measure(
                    server,
                    address,
                    [(query, wire, rcode)],
                    kind,
                    repeat,
                    args.seconds,
                    query_format="edns-do" if args.mode != "unsigned" else "edns",
                    binary_queries=True,
                    load_client=args.load_client,
                    expected_response_wire=received if args.verify_wire else None,
                )
                if args.cpu_handshake and input() != "continue":
                    raise RuntimeError("missing CPU-trial completion acknowledgement")


if __name__ == "__main__":
    main()

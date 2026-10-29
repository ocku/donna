"""Prepare, measure and independently validate a finite signed DNAME workload."""

import argparse
import copy
import json

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.dnssec

from cache_load import measure
from dname_recursive_probe import validated_keys


def request(host, port, owner):
    query = dns.message.make_query(owner, "A", want_dnssec=True, payload=1232)
    reply = dns.query.udp(query, host, port=port, timeout=8)
    assert query.is_response(reply) and reply.rcode() == 0
    assert (
        reply.flags & dns.flags.AD
        and reply.flags & dns.flags.RA
        and not reply.flags & dns.flags.TC
    )
    assert reply.edns == 0 and reply.ednsflags & dns.flags.DO
    return query, reply


def locations(index, count):
    suffix = "" if count == 1 else f"{index % count:02d}"
    return f"old{suffix}.example.test.", f"dest{suffix}.example.test."


def verify_multi(query, response, owner, dname_owner, destination, keys):
    assert (
        query.is_response(response)
        and response.rcode() == 0
        and response.flags & dns.flags.AD
    )
    dnames = [rr for rr in response.answer if rr.rdtype == dns.rdatatype.DNAME]
    cnames = [rr for rr in response.answer if rr.rdtype == dns.rdatatype.CNAME]
    addresses = [rr for rr in response.answer if rr.rdtype == dns.rdatatype.A]
    assert len(dnames) == len(cnames) == len(addresses) == 1
    assert dnames[0].name == dns.name.from_text(dname_owner)
    assert dnames[0][0].target == dns.name.from_text(destination)
    expected = (
        dns.name.from_text(owner)
        .relativize(dnames[0].name)
        .concatenate(dnames[0][0].target)
    )
    assert (
        cnames[0].name == dns.name.from_text(owner) and cnames[0][0].target == expected
    )
    assert cnames[0].ttl <= dnames[0].ttl
    assert addresses[0].name == expected and addresses[0][0].address == "192.0.2.80"
    for data in (dnames[0], addresses[0]):
        signatures = [
            rr
            for rr in response.answer
            if rr.name == data.name
            and rr.rdtype == dns.rdatatype.RRSIG
            and rr.covers == data.rdtype
        ]
        assert signatures
        dns.dnssec.validate(data, signatures[0], keys)
    assert not any(
        rr.rdtype == dns.rdatatype.RRSIG
        and rr.name == cnames[0].name
        and rr.covers == dns.rdatatype.CNAME
        for rr in response.answer
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--repeat", type=int, required=True)
    parser.add_argument("--population", type=int, required=True)
    parser.add_argument("--dnames", type=int, default=1)
    parser.add_argument(
        "--phase", choices=("prepare", "measure", "verify"), required=True
    )
    args = parser.parse_args()
    if not 1 <= args.dnames <= min(64, args.population):
        parser.error("dnames must be 1..min(population, 64)")
    owners = [
        f"p{i:04d}." + locations(i, args.dnames)[0] for i in range(args.population)
    ]
    if args.phase == "prepare":
        # Cache destination A records and chain material, then the DNAMEs.
        for i in range(args.population):
            request(args.host, args.port, f"p{i:04d}." + locations(i, args.dnames)[1])
        keys = validated_keys()
        for i in range(args.dnames):
            old, destination = locations(i, args.dnames)
            owner = "prime." + old
            query, response = request(args.host, args.port, owner)
            verify_multi(query, response, owner, old, destination, keys)
        print(
            json.dumps(
                {
                    "role": args.role,
                    "phase": args.phase,
                    "targets": args.population,
                    "signed_prime": "PASS",
                }
            )
        )
    elif args.phase == "measure":
        queries = [
            dns.message.make_query(owner, "A", want_dnssec=True, payload=1232)
            for owner in owners
        ]
        prepared = [(query, query.to_wire(), 0) for query in queries]
        measure(
            args.role,
            (args.host, args.port),
            prepared,
            "positive",
            args.repeat,
            30,
            query_format="edns-do",
            binary_queries=True,
            max_runs=1,
        )
    else:
        keys = validated_keys()
        for index, owner in enumerate(owners):
            query, response = request(args.host, args.port, owner)
            old, destination = locations(index, args.dnames)
            verify_multi(query, response, owner, old, destination, keys)
            if index == 0:
                broken = copy.deepcopy(response)
                broken.answer = [
                    rr
                    for rr in broken.answer
                    if not (
                        rr.rdtype == dns.rdatatype.RRSIG
                        and rr.covers == dns.rdatatype.DNAME
                    )
                ]
                try:
                    verify_multi(query, broken, owner, old, destination, keys)
                except (AssertionError, dns.exception.DNSException):
                    pass
                else:
                    raise AssertionError("validator accepted missing DNAME signature")
        print(
            json.dumps(
                {
                    "role": args.role,
                    "phase": args.phase,
                    "signed_answers": len(owners),
                    "signature_fault_rejected": True,
                    "verification": "PASS",
                }
            )
        )


if __name__ == "__main__":
    main()

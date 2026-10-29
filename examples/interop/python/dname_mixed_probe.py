"""Validate an authenticated DNAME ending in an unsigned child zone."""

import argparse
import copy
import json

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rcode

import insecure_probe

OLD = dns.name.from_text("old.test.")
TARGET = dns.name.from_text("example.test.")


def verify(request, response, owner, address, keys):
    assert request.is_response(response) and response.rcode() == dns.rcode.NOERROR
    assert response.flags & dns.flags.RA and not response.flags & (
        dns.flags.AD | dns.flags.TC
    )
    dnames = [
        rr
        for rr in response.answer
        if rr.rdtype == dns.rdatatype.DNAME and rr.name == OLD
    ]
    cnames = [
        rr
        for rr in response.answer
        if rr.rdtype == dns.rdatatype.CNAME and rr.name == owner
    ]
    addresses = [rr for rr in response.answer if rr.rdtype == dns.rdatatype.A]
    assert len(dnames) == len(cnames) == len(addresses) == 1
    assert dnames[0][0].target == TARGET
    derived = owner.relativize(OLD).concatenate(TARGET)
    assert cnames[0][0].target == derived and cnames[0].ttl <= dnames[0].ttl
    assert addresses[0].name == derived and str(addresses[0][0]) == address
    signatures = [
        rr
        for rr in response.answer
        if rr.name == OLD
        and rr.rdtype == dns.rdatatype.RRSIG
        and rr.covers == dns.rdatatype.DNAME
    ]
    assert signatures
    dns.dnssec.validate(dnames[0], signatures[0], keys)
    return {
        "dname_ttl": dnames[0].ttl,
        "cname_ttl": cnames[0].ttl,
        "rcode": response.rcode(),
        "ad": bool(response.flags & dns.flags.AD),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("protocol", choices=("udp", "tcp"))
    parser.add_argument("owner")
    parser.add_argument("address")
    parser.add_argument("mode", choices=("nsec", "nsec3"))
    args = parser.parse_args()
    keys = insecure_probe.trusted_parent()
    insecure_probe.parent_proof(keys, args.mode, False)
    owner = dns.name.from_text(args.owner)
    request = dns.message.make_query(owner, "A", want_dnssec=True, payload=1232)
    response = getattr(dns.query, args.protocol)(
        request, args.host, port=args.port, timeout=15
    )
    row = verify(request, response, owner, args.address, keys)
    missing = copy.deepcopy(response)
    missing.answer = [
        rr
        for rr in missing.answer
        if not (rr.rdtype == dns.rdatatype.RRSIG and rr.covers == dns.rdatatype.DNAME)
    ]
    forged = copy.deepcopy(response)
    forged.flags |= dns.flags.AD
    for broken in (missing, forged):
        try:
            verify(request, broken, owner, args.address, keys)
        except (AssertionError, dns.exception.DNSException):
            continue
        raise AssertionError("checker accepted an injected fault")
    row.update(
        {
            "owner": args.owner,
            "faults_rejected": 2,
            "reencoded_hex": response.to_wire().hex(),
        }
    )
    print(json.dumps(row))


if __name__ == "__main__":
    main()

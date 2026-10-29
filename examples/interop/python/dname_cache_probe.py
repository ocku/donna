"""Independently check a DNSSEC-signed DNAME/canonical-address response."""

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
import dns.zone

from dname_recursive_probe import validated_keys


def verify(
    query, response, owner, destination, address, keys, alias=None, alias_keys=None
):
    assert query.is_response(response) and response.rcode() == dns.rcode.NOERROR
    assert response.flags & dns.flags.AD and response.flags & dns.flags.RA
    dnames = [rr for rr in response.answer if rr.rdtype == dns.rdatatype.DNAME]
    cnames = [
        rr
        for rr in response.answer
        if rr.rdtype == dns.rdatatype.CNAME and rr.name == dns.name.from_text(owner)
    ]
    addresses = [rr for rr in response.answer if rr.rdtype == dns.rdatatype.A]
    assert len(dnames) == len(cnames) == len(addresses) == 1
    assert dnames[0].name == dns.name.from_text("old.example.test.")
    actual_destination = dnames[0][0].target.to_text()
    if destination != "either":
        assert dnames[0][0].target == dns.name.from_text(destination)
    else:
        assert actual_destination in ("dest1.example.test.", "dest2.example.test.")
    expected = (
        dns.name.from_text(owner)
        .relativize(dnames[0].name)
        .concatenate(dnames[0][0].target)
    )
    assert (
        cnames[0].name == dns.name.from_text(owner) and cnames[0][0].target == expected
    )
    assert cnames[0].ttl <= dnames[0].ttl
    expected_address = (
        address
        if destination != "either"
        else (
            "192.0.2.2" if actual_destination == "dest1.example.test." else "192.0.2.22"
        )
    )
    assert addresses[0].name == expected and str(addresses[0][0]) == expected_address
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
    if alias is not None:
        aliases = [
            rr
            for rr in response.answer
            if rr.rdtype == dns.rdatatype.CNAME and rr.name == dns.name.from_text(alias)
        ]
        assert len(aliases) == 1 and aliases[0][0].target == dns.name.from_text(owner)
        signatures = [
            rr
            for rr in response.answer
            if rr.name == aliases[0].name
            and rr.rdtype == dns.rdatatype.RRSIG
            and rr.covers == dns.rdatatype.CNAME
        ]
        assert signatures
        dns.dnssec.validate(aliases[0], signatures[0], alias_keys)
    assert not any(
        rr.rdtype == dns.rdatatype.RRSIG
        and rr.name == cnames[0].name
        and rr.covers == dns.rdatatype.CNAME
        for rr in response.answer
    )
    return {
        "owner": owner,
        "destination": actual_destination,
        "address": expected_address,
        "dname_ttl": dnames[0].ttl,
        "cname_ttl": cnames[0].ttl,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("protocol", choices=("udp", "tcp"))
    parser.add_argument("owner")
    parser.add_argument("destination")
    parser.add_argument("address")
    parser.add_argument("--via-alias")
    args = parser.parse_args()
    query = dns.message.make_query(args.via_alias or args.owner, "A", want_dnssec=True)
    response = getattr(dns.query, args.protocol)(
        query, args.host, port=args.port, timeout=8
    )
    keys = validated_keys()
    tld = dns.name.from_text("test.")
    zone = dns.zone.from_file("/work/tld/active.db", origin=tld, relativize=False)
    alias_keys = {tld: zone.get_rdataset(tld, dns.rdatatype.DNSKEY)}
    row = verify(
        query,
        response,
        args.owner,
        args.destination,
        args.address,
        keys,
        args.via_alias,
        alias_keys,
    )
    faults = []
    for covered in (dns.rdatatype.DNAME, dns.rdatatype.A):
        broken = copy.deepcopy(response)
        broken.answer = [
            rr
            for rr in broken.answer
            if not (rr.rdtype == dns.rdatatype.RRSIG and rr.covers == covered)
        ]
        faults.append(broken)
    missing = copy.deepcopy(response)
    missing.answer = [rr for rr in missing.answer if rr.rdtype != dns.rdatatype.CNAME]
    faults.append(missing)
    inflated = copy.deepcopy(response)
    next(
        rr
        for rr in inflated.answer
        if rr.rdtype == dns.rdatatype.CNAME
        and rr.name == dns.name.from_text(args.owner)
    ).ttl = 2**32 - 1
    faults.append(inflated)
    for fault in faults:
        try:
            verify(
                query,
                fault,
                args.owner,
                args.destination,
                args.address,
                keys,
                args.via_alias,
                alias_keys,
            )
        except (AssertionError, dns.exception.DNSException):
            continue
        raise AssertionError("response checker accepted an injected fault")
    row.update(
        {
            "wire_hex": response.to_wire().hex(),
            "authenticated": True,
            "faults_rejected": len(faults),
        }
    )
    print(json.dumps(row))


if __name__ == "__main__":
    main()

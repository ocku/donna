"""Check every signed answer against the selected source and its DNSKEYs."""

import json

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.zone

from signed_probe import nsec3_covers, verify_signatures, witnesses

APEX = dns.name.from_text("example.test.")
SERVERS = (
    ("donna-verified", "172.29.54.10", 5300),
    ("donna-current", "172.29.54.11", 5300),
    ("bind", "172.29.54.20", 53),
    ("knot", "172.29.54.30", 53),
    ("nsd", "172.29.54.40", 53),
)
CASES = (
    ("exact", "www.example.test.", "A", "www.example.test.", "A"),
    ("wildcard", "m.wild.example.test.", "TXT", "*.wild.example.test.", "TXT"),
    ("deep", "p.q.wild.example.test.", "TXT", "*.wild.example.test.", "TXT"),
    ("literal", "*.wild.example.test.", "TXT", "*.wild.example.test.", "TXT"),
    (
        "cname",
        "x.nested.branch.example.test.",
        "CNAME",
        "*.nested.branch.example.test.",
        "CNAME",
    ),
    (
        "cname-chain",
        "x.nested.branch.example.test.",
        "A",
        "*.nested.branch.example.test.",
        "CNAME",
    ),
    ("rrsig", "m.wild.example.test.", "RRSIG", "*.wild.example.test.", "RRSIG"),
    ("any", "m.wild.example.test.", "ANY", "*.wild.example.test.", "ANY"),
)


def inspect(zone, keys, reply, source, kind):
    """Compare individual RRSIGs; validating only one valid signature is insufficient."""
    data = {rr.rdtype: rr for rr in reply.answer if rr.rdtype != dns.rdatatype.RRSIG}
    signatures = [
        sig for rr in reply.answer if rr.rdtype == dns.rdatatype.RRSIG for sig in rr
    ]
    node = zone.get_node(dns.name.from_text(source))
    expected = {
        sig
        for rdataset in node.rdatasets
        if rdataset.rdtype == dns.rdatatype.RRSIG
        for sig in rdataset
        if kind == "RRSIG" or sig.type_covered in data
    }
    details = []
    for sig in signatures:
        valid = None
        if sig.type_covered in data:
            try:
                dns.dnssec.validate_rrsig(data[sig.type_covered], sig, keys)
                valid = True
            except Exception:
                valid = False
        details.append(
            {
                "algorithm": sig.algorithm,
                "labels": sig.labels,
                "key_tag": sig.key_tag,
                "covered": sig.type_covered,
                "source_match": sig in expected,
                "valid": valid,
            }
        )
    passed = (
        set(signatures) == expected
        and len(signatures) == len(expected)
        and bool(expected)
        and all(detail["valid"] is not False for detail in details)
    )
    return passed, details, len(expected)


def proof_valid(reply, keys, name, source, expanded):
    try:
        verify_signatures(reply, keys)
        if expanded:
            qname = dns.name.from_text(name)
            closest = dns.name.from_text(source).parent()
            next_closer = dns.name.Name(
                qname.labels[len(qname.labels) - len(closest.labels) - 1 :]
            )
            return nsec3_covers(witnesses(reply, dns.rdatatype.NSEC3), next_closer)
        return True
    except Exception:
        return False


def answer_shape(reply, kind):
    data = [rr for rr in reply.answer if rr.rdtype != dns.rdatatype.RRSIG]
    if kind == "RRSIG":
        return not data and any(rr.rdtype == dns.rdatatype.RRSIG for rr in reply.answer)
    if kind == "ANY":
        return bool(data)
    return len(data) == 1 and data[0].rdtype == dns.rdatatype.from_text(kind)


def main():
    zone = dns.zone.from_file(
        "/work/signature-source.db", origin=APEX, relativize=False
    )
    keys = {APEX: zone.get_rdataset(APEX, dns.rdatatype.DNSKEY)}
    for server, address, port in SERVERS:
        for case, name, qtype, source, kind in CASES:
            query = dns.message.make_query(name, qtype, want_dnssec=True, payload=1232)
            query.flags &= ~dns.flags.RD
            for protocol in ("udp", "tcp"):
                response = getattr(dns.query, protocol)(
                    query, address, port=port, timeout=3
                )
                shape = (
                    query.is_response(response)
                    and response.rcode() == 0
                    and bool(response.flags & dns.flags.AA)
                    and not response.flags & dns.flags.TC
                    and answer_shape(response, kind)
                )
                passed, details, expected_count = inspect(
                    zone, keys, response, source, kind
                )
                proof = proof_valid(
                    response,
                    keys,
                    name,
                    source,
                    case
                    in ("wildcard", "deep", "cname", "cname-chain", "rrsig", "any"),
                )
                print(
                    json.dumps(
                        {
                            "server": server,
                            "case": case,
                            "protocol": protocol,
                            "passed": bool(shape and passed and proof),
                            "shape": bool(shape),
                            "proof": proof,
                            "signatures": details,
                            "expected_signatures": expected_count,
                            "response_bytes": len(response.to_wire()),
                        }
                    ),
                    flush=True,
                )
        query = dns.message.make_query(
            "m.wild.example.test.", "TXT", want_dnssec=True, payload=512
        )
        query.flags &= ~dns.flags.RD
        udp = dns.query.udp(query, address, port=port, timeout=3)
        truncated = bool(udp.flags & dns.flags.TC)
        final = (
            dns.query.tcp(query, address, port=port, timeout=3) if truncated else udp
        )
        valid, details, expected_count = inspect(
            zone, keys, final, "*.wild.example.test.", "TXT"
        )
        proof = proof_valid(
            final, keys, "m.wild.example.test.", "*.wild.example.test.", True
        )
        shape = (
            query.is_response(udp)
            and len(udp.to_wire()) <= 512
            and query.is_response(final)
            and final.rcode() == 0
            and bool(final.flags & dns.flags.AA)
            and not final.flags & dns.flags.TC
            and answer_shape(final, "TXT")
        )
        print(
            json.dumps(
                {
                    "server": server,
                    "case": "small-udp",
                    "protocol": "udp/tcp" if truncated else "udp",
                    "passed": bool(shape and valid and proof),
                    "shape": bool(shape),
                    "proof": proof,
                    "truncated": truncated,
                    "udp_bytes": len(udp.to_wire()),
                    "signatures": details,
                    "expected_signatures": expected_count,
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()

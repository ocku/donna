"""Ordinary authoritative query semantics compared with independent BIND."""

import itertools
import json

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype

from probe import PROTOCOLS, exchange


def summary(response):
    return {
        "rcode": response.rcode(),
        "aa": bool(response.flags & dns.flags.AA),
        "answer": sorted(
            (r.name.canonicalize().to_text(), r.rdtype, item.to_text())
            for r in response.answer
            for item in r
        ),
        "authority_types": sorted({r.rdtype for r in response.authority}),
    }


def label_boundaries():
    # RFC 1035 names contain arbitrary label octets. A dot inside one label
    # must remain distinct from two labels; cache keys must preserve that too.
    suffix = (b"wild", b"example", b"test", b"")
    names = [
        dns.name.Name(prefix + suffix)
        for prefix in (
            (b"MiXeD",),
            (b"mixed",),
            (b"a.b",),
            (b"a", b"b"),
            (b"zero\x00dot.\xff",),
            (b"X" * 63,),
            (b"x",) * 118,
        )
    ]
    assert len(names[-1].to_wire()) == 255
    for name in names:
        query = dns.message.make_query(name, "TXT", use_edns=0)
        query.flags &= ~dns.flags.RD
        expected = dns.query.udp(query, "172.29.53.20", timeout=3)
        assert expected.answer and expected.answer[0][0].strings == (b"wildcard",)
        for protocol in PROTOCOLS:
            actual = exchange(query, "172.29.53.10", protocol, "/certs/cert.pem")
            assert summary(actual)["answer"] == summary(expected)["answer"], (
                protocol,
                name.to_text(),
                summary(actual),
                summary(expected),
            )
            assert actual.question[0].name.labels == name.labels
        query.flags |= dns.flags.RD
        for protocol in ("udp", "tcp"):
            for _ in range(2):
                actual = getattr(dns.query, protocol)(
                    query, "172.29.53.11", port=5301, timeout=5
                )
                assert actual.rcode() == 0 and actual.answer[0][0].strings == (
                    b"wildcard",
                )
                assert actual.question[0].name.labels == name.labels
    print(
        "PASS binary labels, case, label boundaries, 63-byte labels, 255-byte names and cache reuse",
        flush=True,
    )


def large_rrsets():
    expected_addresses = {f"192.0.2.{index}" for index in range(1, 97)}
    for kind in ("ANY", "A"):
        query = dns.message.make_query(
            "many.example.test.", kind, use_edns=0, payload=512
        )
        expected, _ = dns.query.udp_with_fallback(query, "172.29.53.20", timeout=5)
        assert {
            item.address for rrset in expected.answer for item in rrset
        } == expected_addresses
        for protocol in PROTOCOLS:
            if protocol == "udp":
                actual, used_tcp = dns.query.udp_with_fallback(
                    query, "172.29.53.10", port=5300, timeout=5
                )
                assert used_tcp, (
                    "complete RRset must require TCP with a 512-byte advertisement"
                )
            else:
                actual = exchange(query, "172.29.53.10", protocol, "/certs/cert.pem")
            assert actual.rcode() == 0 and not actual.flags & dns.flags.TC, (
                protocol,
                actual.to_text(),
            )
            assert {
                item.address for rrset in actual.answer for item in rrset
            } == expected_addresses
        # ANY is deliberately first: its cold admission creates both the A
        # projection and aggregate entry at the same owner, then exercises both.
        for protocol in ("udp", "tcp"):
            for _ in range(2):
                if protocol == "udp":
                    actual, _ = dns.query.udp_with_fallback(
                        query, "172.29.53.11", port=5301, timeout=5
                    )
                else:
                    actual = dns.query.tcp(query, "172.29.53.11", port=5301, timeout=5)
                assert actual.rcode() == 0 and not actual.flags & dns.flags.TC
                assert {
                    item.address for rrset in actual.answer for item in rrset
                } == expected_addresses
    print(
        "PASS 96-record A/ANY answers across all transports, fallback and recursive cache admission",
        flush=True,
    )


def main():
    label_boundaries()
    large_rrsets()
    differences = []
    names = (
        "example.test.",
        "www.example.test.",
        "alias.example.test.",
        "wild.example.test.",
        "a.wild.example.test.",
        "a.b.wild.example.test.",
        "missing.example.test.",
        "child.example.test.",
        "www.child.example.test.",
        "delegated-alias.example.test.",
        "external-alias.example.test.",
    )
    # ANY responses may be implementation-selected subsets (RFC 8482), and
    # optional authority/additional data may differ. Compare core semantics.
    for name, kind in itertools.product(
        names, ("A", "AAAA", "CNAME", "NS", "SOA", "DS", "TXT")
    ):
        query = dns.message.make_query(name, kind, use_edns=0)
        query.flags &= ~dns.flags.RD
        expected = dns.query.udp(query, "172.29.53.20", timeout=3)
        try:
            actual = dns.query.udp(query, "172.29.53.10", port=5300, timeout=3)
        except Exception as error:
            differences.append({"name": name, "type": kind, "error": str(error)})
            continue
        left, right = summary(expected), summary(actual)
        # NS authority on a positive response is optional; negative SOA and
        # referrals are meaningful. Ignore optional positive authority.
        if left["answer"]:
            left.pop("authority_types")
            right.pop("authority_types")
        if left != right:
            differences.append(
                {"name": name, "type": kind, "bind": left, "donna": right}
            )
    cases = (
        ("child.example.test.", "DS"),
        ("external-alias.example.test.", "A"),
        ("delegated-alias.example.test.", "A"),
    )
    for protocol, (name, kind) in itertools.product(PROTOCOLS, cases):
        query = dns.message.make_query(name, kind, use_edns=0)
        query.flags &= ~dns.flags.RD
        expected = dns.query.udp(query, "172.29.53.20", timeout=3)
        answer = exchange(query, "172.29.53.10", protocol, "/certs/cert.pem")
        left, right = summary(expected), summary(answer)
        if left["answer"]:
            left.pop("authority_types")
            right.pop("authority_types")
        print(
            json.dumps(
                {"protocol": protocol, "name": name, "type": kind, **summary(answer)}
            ),
            flush=True,
        )
        if left != right:
            differences.append(
                {
                    "protocol": protocol,
                    "name": name,
                    "type": kind,
                    "bind": left,
                    "donna": right,
                }
            )
    print(json.dumps({"semantic_differences": differences}, indent=2), flush=True)
    if differences:
        raise SystemExit(
            f"{len(differences)} ordinary-query semantic differences require RFC review"
        )
    print("PASS independent BIND query semantics", flush=True)


if __name__ == "__main__":
    main()

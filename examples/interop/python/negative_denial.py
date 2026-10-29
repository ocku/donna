"""Public-catalog expectations and mandatory NSEC/NSEC3 denial witnesses."""

import base64
import dns.dnssec
import dns.name
import dns.rdatatype

APEX = dns.name.from_text("example.test.")


def covers(start, end, value):
    return start < value < end if start < end else value > start or value < end


def contains(record, kind):
    value = int(kind)
    for window, bitmap in record.windows:
        index = value % 256
        if window == value // 256 and index // 8 < len(bitmap):
            return bool(bitmap[index // 8] & (0x80 >> (index % 8)))
    return False


class Denial:
    def __init__(self, zone, mode):
        self.zone, self.mode = zone, mode
        self.names = set(zone.nodes)
        for name in tuple(self.names):
            while name != APEX:
                name = name.parent()
                self.names.add(name)

    def closest(self, name):
        while name not in self.names:
            name = name.parent()
        return name

    def expected(self, case):
        name, kind = dns.name.from_text(case["name"]), case["kind"]
        qtype = dns.rdatatype.from_text(case["rtype"])
        assert name.is_subdomain(APEX)
        if kind == "nx":
            assert name not in self.names
            closest = self.closest(name)
            assert dns.name.from_text("*", closest) not in self.names
            return 3, name, closest
        if kind == "wild-nodata":
            assert name not in self.names
            closest = self.closest(name)
            source = dns.name.from_text("*", closest)
            assert (
                source in self.names and self.zone.get_rdataset(source, qtype) is None
            )
            return 0, source, closest
        assert name in self.names
        assert self.zone.get_rdataset(name, qtype) is None
        assert self.zone.get_rdataset(name, dns.rdatatype.CNAME) is None
        if kind == "ent":
            assert self.zone.get_node(name) is None or all(
                data.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.RRSIG)
                for data in self.zone.get_node(name).rdatasets
            )
        if kind == "ds-nodata":
            assert qtype == dns.rdatatype.DS and self.zone.get_rdataset(
                name, dns.rdatatype.NS
            )
        return 0, name, name

    def verify(self, case, response):
        rcode, source, closest = self.expected(case)
        assert response.rcode() == rcode and not response.answer
        qname = dns.name.from_text(case["name"])
        qtype = dns.rdatatype.from_text(case["rtype"])
        proof_type = dns.rdatatype.NSEC if self.mode == "nsec" else dns.rdatatype.NSEC3
        records = [
            (rr.name, item)
            for rr in response.authority
            if rr.rdtype == proof_type
            for item in rr
        ]
        assert records, "missing authenticated denial records"
        if self.mode == "nsec":
            matches = lambda name: [item for owner, item in records if owner == name]
            covered = lambda name: any(
                covers(owner, item.next, name) for owner, item in records
            )
            if rcode == 3:
                assert covered(qname) and covered(dns.name.from_text("*", closest)), (
                    "missing NXDOMAIN/wildcard denial"
                )
                assert any(
                    owner.is_subdomain(closest) or item.next.is_subdomain(closest)
                    for owner, item in records
                )
                return
            if case["kind"] == "ent" and not matches(source):
                assert any(
                    covers(owner, item.next, source) and item.next.is_subdomain(source)
                    for owner, item in records
                ), "missing empty-nonterminal existence proof"
                return
            if case["kind"] == "wild-nodata":
                assert covered(qname), "missing wildcard expansion denial"
        else:
            assert (
                len(
                    {
                        (item.algorithm, item.iterations, item.salt)
                        for _, item in records
                    }
                )
                == 1
            )
            assert all(
                item.algorithm == 1 and item.iterations == 0 and item.flags == 0
                for _, item in records
            )
            digest = lambda name, item: dns.dnssec.nsec3_hash(
                name, item.salt, item.iterations, item.algorithm
            )
            matches = lambda name: [
                item
                for owner, item in records
                if owner.labels[0].decode().upper() == digest(name, item)
            ]

            def covered(name):
                return any(
                    covers(
                        owner.labels[0].decode().upper(),
                        base64.b32hexencode(item.next).decode().rstrip("="),
                        digest(name, item),
                    )
                    for owner, item in records
                )

            if rcode == 3 or case["kind"] == "wild-nodata":
                next_closer = dns.name.Name(qname.labels[-len(closest.labels) - 1 :])
                assert matches(closest) and covered(next_closer), (
                    "missing closest-encloser/next-closer proof"
                )
                if rcode == 3:
                    assert covered(dns.name.from_text("*", closest)), (
                        "missing wildcard denial"
                    )
                    return
        bitmap = matches(source)
        assert bitmap and all(
            not contains(item, qtype) and not contains(item, dns.rdatatype.CNAME)
            for item in bitmap
        )
        if case["kind"] == "ds-nodata":
            assert all(
                contains(item, dns.rdatatype.NS)
                and not contains(item, dns.rdatatype.SOA)
                for item in bitmap
            )

    def relevant(self, case, rr):
        rcode, source, closest = self.expected(case)
        if rr.rdtype == dns.rdatatype.SOA:
            return True
        name = dns.name.from_text(case["name"])
        wildcard = dns.name.from_text("*", closest)
        for item in rr:
            if rr.rdtype == dns.rdatatype.NSEC:
                if rcode == 3 and (
                    covers(rr.name, item.next, name)
                    or covers(rr.name, item.next, wildcard)
                ):
                    return True
                if not rcode and (
                    rr.name == source
                    or case["kind"] == "ent"
                    and covers(rr.name, item.next, source)
                    and item.next.is_subdomain(source)
                ):
                    return True
                if case["kind"] == "wild-nodata" and covers(rr.name, item.next, name):
                    return True
            elif rr.rdtype == dns.rdatatype.NSEC3:
                start = rr.name.labels[0].decode().upper()
                end = base64.b32hexencode(item.next).decode().rstrip("=")
                digest = lambda owner: dns.dnssec.nsec3_hash(
                    owner, item.salt, item.iterations, item.algorithm
                )
                next_closer = dns.name.Name(name.labels[-len(closest.labels) - 1 :])
                if rcode == 3 and (
                    start == digest(closest)
                    or covers(start, end, digest(next_closer))
                    or covers(start, end, digest(wildcard))
                ):
                    return True
                if not rcode and start == digest(source):
                    return True
                if case["kind"] == "wild-nodata" and (
                    start == digest(closest) or covers(start, end, digest(next_closer))
                ):
                    return True
        return False

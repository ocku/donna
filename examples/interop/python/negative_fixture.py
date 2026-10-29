"""Bounded signed negative-cache populations; fresh passes never repeat names."""

import random

from recursive_fixture import prefix, request
from recursive_fixture import frame as frame

APEX = "example.test."
SEEDS = {
    "descendant": dict(name="gone." + APEX, rtype="A", kind="nx"),
    "sibling": dict(name="m-prime.range." + APEX, rtype="A", kind="nx"),
}


def cases(kind):
    if kind == "exact":
        result = [
            dict(
                name=prefix(index) + ".exact." + APEX,
                rtype="A" if index % 2 == 0 else "AAAA",
                kind="nx",
            )
            for index in range(256)
        ]
    else:
        suffix = ".gone." if kind == "descendant" else ".range."
        result = [
            dict(name=("m" + prefix(index)) + suffix + APEX, rtype="A", kind="nx")
            for index in range(512)
        ]
    random.Random(0x80208198).shuffle(result)
    return result


def inputs(kind):
    return [request(case) for case in cases(kind)]


def additions():
    return """
exact IN TXT "closest"
a.exact IN TXT "left"
z.exact IN TXT "right"
range IN TXT "closest"
a.range IN TXT "left"
z.range IN TXT "right"
g0 IN TXT "left"
gz IN TXT "right"
present IN TXT "no-address-at-owner"
child.present IN A 192.0.2.90
leaf.branch IN A 192.0.2.91
*.wild IN TXT "wildcard"
cut IN NS ns.cut.example.test.
ns.cut IN A 172.29.53.71
"""


def guards():
    return [
        dict(name="present." + APEX, rtype="A", kind="nodata"),
        dict(name="present." + APEX, rtype="AAAA", kind="nodata"),
        dict(
            name="child.present." + APEX, rtype="A", kind="positive", value="192.0.2.90"
        ),
        dict(name="branch." + APEX, rtype="A", kind="ent"),
        dict(name="missing.branch." + APEX, rtype="A", kind="nx"),
        dict(
            name="leaf.branch." + APEX, rtype="A", kind="positive", value="192.0.2.91"
        ),
        dict(name="random.wild." + APEX, rtype="A", kind="wild-nodata"),
        dict(name="cut." + APEX, rtype="DS", kind="ds-nodata"),
        dict(
            name="live.cut." + APEX,
            rtype="A",
            kind="insecure-positive",
            value="192.0.2.92",
        ),
    ]


CHILD = """$ORIGIN cut.example.test.
$TTL 300
@ IN SOA ns.cut.example.test. hostmaster.cut.example.test. 1 60 60 3600 5
@ IN NS ns.cut.example.test.
ns IN A 172.29.53.71
live IN A 192.0.2.92
"""

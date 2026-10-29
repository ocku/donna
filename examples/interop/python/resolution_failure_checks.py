"""Normalized unsigned resolution-failure gates, without DNS dependencies."""

from recursive_cache_checks import total


def validate(name, kind, cd, expected, response):
    assert response["rcode"] == expected, "wrong failure/recovery RCODE"
    flags = response["flags"]
    assert flags & 0x80 and flags & 0x100, "RD/RA required"
    assert not flags & (0x400 | 0x20 | 0x200), "wrong AA/AD/TC"
    assert bool(flags & 0x10) == cd, "client CD not copied"
    if expected == 2:
        assert not response["answer"], "generic failure must not invent an answer"
    else:
        data = "2001:db8::90" if kind == "AAAA" else "192.0.2.90"
        assert response["answer"] == [(name, kind, "IN", data)], (
            "wrong healthy/recovered data"
        )


def traffic_matches(before, after, name, reuse):
    delta = total(after, name) - total(before, name)
    return delta == 0 if reuse else delta > 0

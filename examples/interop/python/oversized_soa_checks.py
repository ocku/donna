"""Independent checks on retained malformed-SOA comparison observations."""

import json
import sys


def validate(observations):
    assert len(observations) == 14
    rows = {(r["server"], r["protocol"], r["stage"]): r for r in observations}
    assert len(rows) == len(observations), "duplicate observation"
    for protocol in ("udp", "tcp"):
        direct = rows[("authority", protocol, "direct")]
        assert (direct["rcode"], direct["soa_ttl"], direct["minimum"]) == (
            "NXDOMAIN",
            20,
            6,
        )
        for server in ("donna", "bind"):
            cold = rows[(server, protocol, "cold")]
            warm = rows[(server, protocol, "warm")]
            after = rows[(server, protocol, "after-minimum")]
            assert (
                cold["rcode"] == "NXDOMAIN"
                and cold["upstream_after"] > cold["upstream_before"]
            )
            assert (
                warm["rcode"] == "NXDOMAIN"
                and warm["upstream_after"] == warm["upstream_before"]
            )
            for row in (cold, warm):
                assert row["answers"] == [] and len(row["soas"]) == 1
                owner, ttl, minimum = row["soas"][0]
                assert owner == "example.test." and 0 <= ttl <= 20 and minimum == 6
            if server == "donna":
                assert warm["soas"][0][1] <= 6
                assert (
                    after["rcode"] == "NOERROR"
                    and after["upstream_after"] > after["upstream_before"]
                )
                assert after["answers"] == [
                    [f"oversized-soa-{server}-{protocol}.example.test.", "192.0.2.99"]
                ]


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as source:
        validate(json.load(source)["observations"])
    print("PASS: 14 independently checked observations")

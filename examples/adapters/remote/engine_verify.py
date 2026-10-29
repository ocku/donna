"""Offline public-key check of library replies and retained acquisition witnesses."""

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdatatype

from negative_denial import Denial
from recursive_evidence import authenticated_keys, record_key, rrset, zones


def case(label):
    kind = label.rsplit("-", 1)[-1]
    if label.startswith("expiry-"):
        return dict(
            kind="direct", name="expire.example.test.", rtype="A", value="192.0.2.81"
        )
    if label.startswith("corruption-") or label.startswith("disabled-"):
        kind = "a"
    if kind in ("a", "aaaa", "txt"):
        return dict(
            kind="direct",
            name="coherence.example.test.",
            rtype=kind.upper(),
            value={"a": "192.0.2.84", "aaaa": "2001:db8::84", "txt": '"coherence"'}[
                kind
            ],
        )
    if kind == "dname":
        return dict(
            kind=kind, name="prime.old.example.test.", rtype="A", value="192.0.2.80"
        )
    assert kind in ("negative", "descendant")
    return dict(
        kind="nx",
        name=("new.gone." if kind == "descendant" else "gone.") + "example.test.",
        rtype="AAAA" if kind == "descendant" else "A",
    )


def identity(rr, sig):
    return (
        record_key(rr)
        + hashlib.sha256(
            b"".join(sorted(s.to_wire(canonicalize=True) for s in sig))
        ).hexdigest()
    )


def matching_signatures(message, rr):
    found = [
        s
        for s in message.answer + message.authority
        if s.rdtype == dns.rdatatype.RRSIG
        and s.name == rr.name
        and s.covers == rr.rdtype
    ]
    assert len(found) == 1 and found[0]
    return found[0]


def verify(public, runs):
    leaf = zones(public)["leaf"]
    oracle = Denial(leaf, "nsec")
    replies = signatures = ttl_checks = upstream_packets = ds_witnesses = 0
    assert all(type(r["exit_code"]) is int and r["exit_code"] == 0 for r in runs)
    assert all(isinstance(r["container"], str) and r["container"].strip() for r in runs)
    assert len({r["container"] for r in runs}) == len(runs)
    assert [(r["binary"], r["mode"]) for r in runs] == [
        ("cache-engine", mode)
        for mode in (
            "seed",
            "verify",
            "cache-unavailable",
            "catalog-unavailable",
            "verify",
        )
    ]
    expected_counts = {"seed": 37, "verify": 18}
    for run in runs:
        if run["mode"] not in expected_counts:
            continue
        kinds = ("a", "aaaa", "txt", "dname", "negative", "descendant")
        expected = [
            f"{prefix}-{kind}"
            for prefix in ("provider-first", "provider-repeat", "restarted")
            for kind in kinds
        ]
        if run["mode"] == "seed":
            expected += [
                f"default-{step}-{kind}"
                for step in ("first", "repeat")
                for kind in kinds
            ]
            expected += [
                "disabled-a",
                "disabled-a",
                "expiry-first",
                "expiry-repeat",
                "expiry-after",
                "corruption-first",
                "corruption-repaired",
            ]
        assert Counter(
            line.split()[1]
            for line in run["output"].splitlines()
            if line.startswith("REPLY ")
        ) == Counter(expected)
        ledger = {}
        pending = {}
        seen = []
        for line in run["output"].splitlines():
            if line.startswith("DS-WITNESS "):
                _, wall, query, response = line.split()
                when = int(wall) / 1e9
                q = dns.message.from_wire(bytes.fromhex(query))
                r = dns.message.from_wire(bytes.fromhex(response))
                assert q.is_response(r)
                parsed = zones(public)
                owner = dns.name.from_text("example.test.")
                tld = dns.name.from_text("test.")
                ds = next(rr for rr in r.answer if rr.rdtype == dns.rdatatype.DS)
                bad = zones(public, bad=True)["tld"]
                assert set(ds) == set(rrset(bad, owner, dns.rdatatype.DS))
                assert set(ds) != set(rrset(parsed["tld"], owner, dns.rdatatype.DS))
                authenticated_keys(public, when)
                dns.dnssec.validate(
                    ds,
                    matching_signatures(r, ds),
                    {tld: rrset(parsed["tld"], tld, dns.rdatatype.DNSKEY)},
                    now=when,
                )
                assert not any(
                    dns.dnssec.make_ds(owner, key, "SHA256") in ds
                    for key in rrset(leaf, owner, dns.rdatatype.DNSKEY)
                )
                ds_witnesses += 1
                continue
            if line.startswith("UPSTREAM "):
                _, label, wall, mono, query, response = line.split()
                q = dns.message.from_wire(bytes.fromhex(query))
                r = dns.message.from_wire(bytes.fromhex(response))
                assert q.is_response(r)
                pending.setdefault(label, []).append((int(wall) / 1e9, int(mono), r))
                upstream_packets += 1
                continue
            if not line.startswith("REPLY "):
                continue
            _, label, wall, mono, delta, wire = line.split()
            when, mono = float(int(wall) / 1e9), int(mono)
            response = dns.message.from_wire(bytes.fromhex(wire))
            wanted = case(label)
            seen.append(label)
            assert len(response.question) == 1 and response.question[
                0
            ].name == dns.name.from_text(wanted["name"])
            assert (
                response.question[0].rdtype == dns.rdatatype.from_text(wanted["rtype"])
                and response.question[0].rdclass == 1
            )
            assert (
                response.flags & dns.flags.QR
                and response.flags & dns.flags.AD
                and not response.flags & dns.flags.TC
            )
            keys = authenticated_keys(public, when)
            observed = {
                (rr.name.to_text(), dns.rdatatype.to_text(rr.rdtype), item.to_text())
                for rr in response.answer
                if rr.rdtype != dns.rdatatype.RRSIG
                for item in rr
            }
            if wanted["kind"] == "nx":
                oracle.verify(wanted, response)
            else:
                target = (
                    "prime.dest.example.test."
                    if wanted["kind"] == "dname"
                    else wanted["name"]
                )
                expected = {(target, wanted["rtype"], wanted["value"])}
                if wanted["kind"] == "dname":
                    expected |= {
                        ("old.example.test.", "DNAME", "dest.example.test."),
                        ("prime.old.example.test.", "CNAME", target),
                    }
                assert response.rcode() == 0 and observed == expected
            group = (
                "default"
                if label.startswith("default-")
                else (
                    "expiry"
                    if label.startswith("expiry-")
                    else (
                        "corruption"
                        if label.startswith("corruption-")
                        else (
                            "disabled" if label.startswith("disabled-") else "provider"
                        )
                    )
                )
            )
            acquisitions = pending.pop(label, [])
            assert len(acquisitions) == int(delta)
            if label.startswith("expiry-after"):
                assert acquisitions
            for rr in response.answer + response.authority:
                if rr.rdtype == dns.rdatatype.RRSIG:
                    continue
                if rr.rdtype == dns.rdatatype.CNAME and wanted["kind"] == "dname":
                    source = next(
                        x for x in response.answer if x.rdtype == dns.rdatatype.DNAME
                    )
                    assert rr.ttl <= source.ttl and rr[0].target == rr.name.relativize(
                        source.name
                    ).concatenate(source[0].target)
                    assert not any(
                        s.rdtype == dns.rdatatype.RRSIG
                        and s.name == rr.name
                        and s.covers == dns.rdatatype.CNAME
                        for s in response.answer
                    )
                    continue
                original = rrset(leaf, rr.name, rr.rdtype)
                assert set(rr) == set(original)
                sig = matching_signatures(response, rr)
                assert sig[0].signer == dns.name.from_text("example.test.")
                dns.dnssec.validate(rr, sig, keys, now=when)
                signatures += 1
                upper = original.ttl
                if rr.rdtype == dns.rdatatype.SOA:
                    upper = min(upper, original[0].minimum)
                assert 0 <= rr.ttl <= upper and 0 <= sig.ttl <= upper
                key = group, identity(rr, sig)
                # Only a completed authority response carrying this exact signed
                # RRset can renew it; unrelated DNSKEY/NS requests cannot.
                for acquired_wall, acquired_mono, message in acquisitions:
                    for fresh in message.answer + message.authority:
                        if (
                            fresh.rdtype == rr.rdtype
                            and fresh.name == rr.name
                            and set(fresh) == set(rr)
                        ):
                            fsig = matching_signatures(message, fresh)
                            if identity(fresh, fsig) != key[1]:
                                continue
                            dns.dnssec.validate(fresh, fsig, keys, now=acquired_wall)
                            deadline = (
                                acquired_mono
                                + min(fresh.ttl, fsig.ttl, upper) * 1_000_000_000
                            )
                            ledger[key] = max(ledger.get(key, 0), deadline)
                if key in ledger:
                    remaining = (ledger[key] - mono) / 1e9
                    assert mono <= ledger[key] + 1_000_000_000
                    assert max(rr.ttl, sig.ttl) <= math.ceil(max(0, remaining)), (
                        label,
                        rr,
                        remaining,
                    )
                else:
                    ledger[key] = mono + min(rr.ttl, sig.ttl) * 1_000_000_000
                ttl_checks += 2
            replies += 1
        assert len(seen) == expected_counts[run["mode"]] and not pending, (
            run["mode"],
            len(seen),
        )
    assert replies == 73 and ds_witnesses == 1
    try:
        authenticated_keys(
            public,
            next(
                int(line.split()[2]) / 1e9
                for run in runs
                for line in run["output"].splitlines()
                if line.startswith("REPLY ")
            ),
            bad=True,
        )
    except Exception:
        pass
    else:
        raise AssertionError("deliberately bad DS chain must fail")
    return dict(
        replies=replies,
        authenticated_rrsets=signatures,
        ttl_checks=ttl_checks,
        completed_authority_responses=upstream_packets,
        bogus_ds_served_witnesses=ds_witnesses,
        network="none",
        private_signing_keys=0,
        scope="Library adapter replies; no transport-front-end RD/RA/EDNS conformance or throughput claim. Per-process monotonic aging; restart authentication also relies on core seal/expiry checks.",
    )


if __name__ == "__main__":
    data = json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(verify(data["public"], data["runs"])), flush=True)

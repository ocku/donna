"""Synthetic signed provider scenarios for the offline verifier's fault tests.

These inputs model reply/acquisition records. They are not captures of Donna,
database activity, container execution, or a measured cache lifetime.
"""

from functools import lru_cache

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from recursive_evidence import rrset, zones
from test_fixtures.signed import APEX, WHEN, chain, unsigned

SECOND_NS = 1_000_000_000
MONOTONIC_NS = 100 * SECOND_NS
KINDS = ("a", "aaaa", "txt", "dname", "negative", "descendant")
MODES = ("seed", "verify", "cache-unavailable", "catalog-unavailable", "verify")
QUESTIONS = {
    "a": ("coherence.example.test.", "A"),
    "aaaa": ("coherence.example.test.", "AAAA"),
    "txt": ("coherence.example.test.", "TXT"),
    "dname": ("prime.old.example.test.", "A"),
    "negative": ("gone.example.test.", "A"),
    "descendant": ("new.gone.example.test.", "AAAA"),
    "expiry": ("expire.example.test.", "A"),
}


def catalog():
    records = (
        "coherence IN A 192.0.2.84\n"
        "coherence IN AAAA 2001:db8::84\n"
        'coherence IN TXT "coherence"\n'
        "old IN DNAME dest.example.test.\n"
        "prime.dest IN A 192.0.2.80\n"
        "expire 5 IN A 192.0.2.81\n"
    )
    zone = unsigned(APEX, records)
    owners = sorted(zone.nodes)
    for index, owner in enumerate(owners):
        kinds = {dataset.rdtype for dataset in zone.nodes[owner].rdatasets}
        kinds.update((dns.rdatatype.RRSIG, dns.rdatatype.NSEC))
        if owner == zone.origin:
            kinds.add(dns.rdatatype.DNSKEY)
        bitmap = " ".join(dns.rdatatype.to_text(kind) for kind in sorted(kinds))
        records += f"{owner} IN NSEC {owners[(index + 1) % len(owners)]} {bitmap}\n"
    return chain(records)


def signed_pair(zone, owner, kind, ttl=None):
    if isinstance(owner, str):
        owner = dns.name.from_text(owner)
    records = [
        rrset(zone, owner, kind),
        rrset(zone, owner, dns.rdatatype.RRSIG, kind),
    ]
    if ttl is not None:
        for record in records:
            record.ttl = min(record.ttl, ttl)
    return records


def response(zone, label):
    if label.startswith("expiry-"):
        kind = "expiry"
    elif label.startswith(("corruption-", "disabled-")):
        kind = "a"
    else:
        kind = label.rsplit("-", 1)[-1]
    owner, qtype = QUESTIONS[kind]
    query = dns.message.make_query(owner, qtype)
    query.id = 0xBEEF
    reply = dns.message.make_response(query)
    reply.flags |= dns.flags.AD
    if kind in ("negative", "descendant"):
        reply.set_rcode(dns.rcode.NXDOMAIN)
        reply.authority.extend(signed_pair(zone, APEX, dns.rdatatype.SOA, 5))
        for owner, _ in zone.iterate_rdatasets(dns.rdatatype.NSEC):
            reply.authority.extend(signed_pair(zone, owner, dns.rdatatype.NSEC, 5))
    elif kind == "dname":
        reply.answer.extend(signed_pair(zone, "old." + APEX, dns.rdatatype.DNAME))
        reply.answer.append(
            dns.rrset.from_text(owner, 300, "IN", "CNAME", "prime.dest." + APEX)
        )
        reply.answer.extend(signed_pair(zone, "prime.dest." + APEX, dns.rdatatype.A))
    else:
        ttl = 4 if label == "expiry-repeat" else None
        reply.answer.extend(
            signed_pair(zone, owner, dns.rdatatype.from_text(qtype), ttl)
        )
    return query, reply


def labels(mode):
    result = [
        f"{prefix}-{kind}"
        for prefix in ("provider-first", "provider-repeat", "restarted")
        for kind in KINDS
    ]
    if mode == "seed":
        result += [
            f"default-{step}-{kind}" for step in ("first", "repeat") for kind in KINDS
        ]
        result += [
            "disabled-a",
            "disabled-a",
            "expiry-first",
            "expiry-repeat",
            "expiry-after",
            "corruption-first",
            "corruption-repaired",
        ]
    return result


def ds_witness(public):
    query = dns.message.make_query(APEX, "DS")
    reply = dns.message.make_response(query)
    reply.answer.extend(
        signed_pair(zones(public, bad=True)["tld"], APEX, dns.rdatatype.DS)
    )
    return (
        f"DS-WITNESS {WHEN * SECOND_NS} {query.to_wire().hex()} {reply.to_wire().hex()}"
    )


def output(public, zone, mode):
    lines = [ds_witness(public)] if mode == "seed" else []
    for label in labels(mode):
        age = {"expiry-repeat": 1, "expiry-after": 6}.get(label, 0)
        wall = (WHEN + age) * SECOND_NS
        mono = MONOTONIC_NS + age * SECOND_NS
        query, reply = response(zone, label)
        acquired = int(label == "expiry-after")
        if acquired:
            lines.append(
                f"UPSTREAM {label} {wall} {mono} {query.to_wire().hex()} {reply.to_wire().hex()}"
            )
        lines.append(f"REPLY {label} {wall} {mono} {acquired} {reply.to_wire().hex()}")
    return "\n".join(lines) + "\n"


@lru_cache
def record():
    public = catalog()
    zone = zones(public)["leaf"]
    runs = []
    for index, mode in enumerate(MODES):
        runs.append(
            dict(
                binary="cache-engine",
                mode=mode,
                container=f"synthetic-cache-engine-{index}",
                exit_code=0,
                output=output(public, zone, mode)
                if mode in ("seed", "verify")
                else "Synthetic unchecked-run placeholder; no execution claim.\n",
            )
        )
    return dict(
        scope="Synthetic signed verifier model; no historical or live execution evidence.",
        public=public,
        runs=runs,
    )

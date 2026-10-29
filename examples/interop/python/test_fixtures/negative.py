"""Construct signed negative replies as oracle models, without network traffic."""

from functools import lru_cache

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import dns.zone

from .signed import APEX, WHEN, chain

MONOTONIC_NS = 100_000_000_000
NEGATIVE_TTL = 5


def data(zone, owner, kind):
    dataset = zone.get_rdataset(owner, kind)
    return dns.rrset.from_rdata_list(
        dns.name.from_text(owner), dataset.ttl, list(dataset)
    )


def signed_pair(zone, owner, kind):
    records = [data(zone, owner, kind)]
    signatures = zone.get_rdataset(owner, dns.rdatatype.RRSIG, covers=kind)
    records.append(
        dns.rrset.from_rdata_list(
            dns.name.from_text(owner), signatures.ttl, list(signatures)
        )
    )
    for record in records:
        record.ttl = NEGATIVE_TTL
    return records


def catalog(mode):
    records = 'g0 IN TXT "left"\ngz IN TXT "right"\n'
    owners = [APEX, "g0." + APEX, "gz." + APEX, "ns." + APEX]
    if mode == "nsec":
        for index, owner in enumerate(owners):
            kinds = (
                "SOA NS DNSKEY"
                if owner == APEX
                else "A"
                if owner.startswith("ns.")
                else "TXT"
            )
            records += f"{owner} IN NSEC {owners[(index + 1) % len(owners)]} {kinds} RRSIG NSEC\n"
    else:
        hashes = sorted(
            (dns.dnssec.nsec3_hash(owner, "", 0, 1), owner) for owner in owners
        )
        for index, (digest, owner) in enumerate(hashes):
            following = hashes[(index + 1) % len(hashes)][0]
            kinds = (
                "SOA NS DNSKEY"
                if owner == APEX
                else "A"
                if owner.startswith("ns.")
                else "TXT"
            )
            records += f"{digest}.{APEX} IN NSEC3 1 0 0 - {following} {kinds} RRSIG\n"
    public = dict(chain(records), denial=mode)
    zone = dns.zone.from_text(public["zones"]["leaf"], origin=APEX, relativize=False)
    return public, zone


def capture(zone, mode, name, step, *, unsigned_ns=False):
    case = dict(name=name, rtype="A", kind="nx")
    query = dns.message.make_query(name, "A", want_dnssec=True, payload=1232)
    query.id = 0xBEEF
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    response.flags |= dns.flags.RA | dns.flags.AD
    response.use_edns(0, ednsflags=dns.flags.DO, payload=1232)
    response.authority.extend(signed_pair(zone, APEX, dns.rdatatype.SOA))
    proof_type = dns.rdatatype.NSEC if mode == "nsec" else dns.rdatatype.NSEC3
    proof_owners = (
        [APEX, "g0." + APEX]
        if mode == "nsec"
        else [owner.to_text() for owner, _ in zone.iterate_rdatasets(proof_type)]
    )
    for owner in proof_owners:
        response.authority.extend(signed_pair(zone, owner, proof_type))
    if unsigned_ns:
        response.authority.append(data(zone, APEX, dns.rdatatype.NS))
    # Monotonic receipt times and declining TTLs model three successive replies.
    age = step
    for record in response.authority:
        record.ttl = max(0, record.ttl - age)
    return dict(
        case=case,
        query=query.to_wire().hex(),
        response=response.to_wire().hex(),
        checked_at=WHEN + age,
        received_monotonic_ns=MONOTONIC_NS + age * 1_000_000_000,
    )


@lru_cache
def negative_record():
    public, observations = {}, []
    for mode in ("nsec", "nsec3"):
        public[mode], zone = catalog(mode)
        for step, name in enumerate(
            ("gone." + APEX, "gone." + APEX, "child.gone." + APEX)
        ):
            packet = capture(zone, mode, name, step)
            observations.append(
                dict(
                    mode=mode,
                    role="model",
                    scenario="descendant",
                    step=step,
                    case=packet["case"],
                    capture=packet,
                )
            )
        packet = capture(zone, mode, "gone." + APEX, 1, unsigned_ns=True)
        observations.append(
            dict(
                mode=mode,
                role="unsigned-authority-model",
                scenario="descendant",
                step=1,
                case=packet["case"],
                capture=packet,
            )
        )
    return dict(public=public, observations=observations)

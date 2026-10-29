"""Small, freshly signed DNS catalogs built independently of Donna's encoder."""

from functools import lru_cache
import time

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rrset
import dns.zone

WHEN = 1_750_000_000
LIFETIME = 86_400
TTL = 300
APEX = "example.test."


def key(seed, algorithm="ECDSAP256SHA256"):
    if algorithm == "ED25519":
        private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    else:
        private = ec.derive_private_key(seed, ec.SECP256R1())
    return private, dns.dnssec.make_dnskey(private.public_key(), algorithm, flags=257)


def unsigned(origin, records="", keys=()):
    text = (
        f"$ORIGIN {origin}\n$TTL {TTL}\n"
        "@ IN SOA ns hostmaster 1 60 60 3600 5\n@ IN NS ns\n"
        "ns IN A 192.0.2.53\n"
    )
    text += "".join(f"@ IN DNSKEY {item.to_text()}\n" for _, item in keys)
    return dns.zone.from_text(text + records, origin=origin, relativize=False)


def sign(zone, keys, when=WHEN):
    for owner, dataset in list(zone.iterate_rdatasets()):
        if dataset.rdtype == dns.rdatatype.RRSIG:
            continue
        data = dns.rrset.from_rdata_list(owner, dataset.ttl, list(dataset))
        for private, public in keys:
            signature = dns.dnssec.sign(
                data,
                private,
                zone.origin,
                public,
                inception=when - 600,
                expiration=when + LIFETIME,
            )
            zone.find_rdataset(
                owner, dns.rdatatype.RRSIG, dataset.rdtype, create=True
            ).add(signature, dataset.ttl)
    return zone


@lru_cache
def chain(leaf_records):
    origins = {"root": ".", "tld": "test.", "leaf": APEX}
    keys = {name: [key(index)] for index, name in enumerate(origins, 1)}
    leaf = sign(unsigned(APEX, leaf_records, keys["leaf"]), keys["leaf"])
    leaf_ds = dns.dnssec.make_ds(APEX, keys["leaf"][0][1], "SHA256")
    tld = sign(unsigned("test.", f"{APEX} IN DS {leaf_ds}\n", keys["tld"]), keys["tld"])
    tld_ds = dns.dnssec.make_ds("test.", keys["tld"][0][1], "SHA256")
    root = sign(unsigned(".", f"test. IN DS {tld_ds}\n", keys["root"]), keys["root"])
    wrong_ds = dns.dnssec.make_ds(APEX, key(99)[1], "SHA256")
    bad_tld = sign(
        unsigned("test.", f"{APEX} IN DS {wrong_ds}\n", keys["tld"]), keys["tld"]
    )
    return dict(
        origins=origins,
        anchors=f". {TTL} IN DNSKEY {keys['root'][0][1]}\n",
        zones={
            name: zone.to_text(relativize=False)
            for name, zone in (("root", root), ("tld", tld), ("leaf", leaf))
        },
        bad_tld=bad_tld.to_text(relativize=False),
    )


def recursive_chain():
    return chain("old IN DNAME dest.example.test.\np0000.dest IN A 192.0.2.80\n")


def signature_sources():
    keys = [key(4), key(5, "ED25519")]
    return sign(
        unsigned(APEX, "www IN A 192.0.2.80\n* IN A 192.0.2.99\n", keys),
        keys,
        when=int(time.time()),
    )

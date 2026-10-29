"""Corrupt denial signatures in a public fixture; never handles private keys."""

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.zone

zone = dns.zone.from_file("/work/tld/active.db", origin="test.", relativize=False)
changed = 0
for _, node in zone.nodes.items():
    for kind in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
        signatures = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, kind)
        if signatures:
            original = list(signatures)
            signatures.clear()
            for sig in original:
                raw = bytes(sig.signature)
                signatures.add(sig.replace(signature=bytes([raw[0] ^ 1]) + raw[1:]))
                changed += 1
assert changed > 0, "no denial signatures to corrupt"
zone.to_file("/tmp/tld-bad-denial.db", relativize=False)
print(changed)

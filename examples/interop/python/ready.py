import socket
import sys
import time

import dns.exception
import dns.message
import dns.query
import dns.rcode

targets = [
    ("172.29.53.10", 5300),
    ("172.29.53.11", 5301),
    ("172.29.53.12", 5301),
    ("172.29.53.20", 53),
    ("172.29.53.21", 53),
    ("172.29.53.22", 53),
    ("172.29.53.30", 8530),
]
deadline = time.monotonic() + 30
while targets and time.monotonic() < deadline:
    for target in targets[:]:
        try:
            with socket.create_connection(target, timeout=0.2):
                targets.remove(target)
        except OSError:
            pass
    time.sleep(0.1)
if targets:
    sys.exit(f"listeners unavailable: {targets}")

# A listening BIND socket does not establish that its zone loaded successfully.
checks = [
    ("172.29.53.10", 5300, "example.test.", "SOA"),
    ("172.29.53.11", 5301, "www.example.test.", "A"),
    ("172.29.53.12", 5301, "example.test.", "SOA"),
    ("172.29.53.20", 53, "example.test.", "SOA"),
    ("172.29.53.21", 53, "test.", "SOA"),
    ("172.29.53.22", 53, ".", "SOA"),
]
errors = {}
while checks and time.monotonic() < deadline:
    for check in checks[:]:
        host, port, name, kind = check
        try:
            response = dns.query.tcp(
                dns.message.make_query(name, kind), host, port=port, timeout=0.3
            )
            if response.rcode() == dns.rcode.NOERROR and response.answer:
                checks.remove(check)
            else:
                errors[check] = response.to_text()
        except (OSError, dns.exception.DNSException) as error:
            errors[check] = str(error)
    time.sleep(0.1)
if checks:
    sys.exit(
        f"DNS services not ready: {[(check, errors.get(check)) for check in checks]}"
    )
print("All laboratory services accept connections and DNS zones answer queries")

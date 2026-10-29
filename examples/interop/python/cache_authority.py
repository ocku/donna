"""Independent unsigned authority with observable requests and short-lived data.

Runs only inside the existing peers image. HTTP is isolated fixture control,
never a Donna feature. Counter reads and generation changes share one lock.
"""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socketserver
import struct
import threading

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

HOST = os.environ.get("AUTHORITY_HOST", "172.29.55.20")
ZONE = "example.test."
LOCK = threading.Lock()
COUNTS = Counter()
GENERATION = 0


def rr(owner, kind, value, ttl=6):
    return dns.rrset.from_text(owner, ttl, "IN", kind, value)


def ttl_answer(response, name):
    kind = name.split("-")[1]
    ttls = {
        "normal": [20, 20],
        "mixed": [20, 6],
        "reversed": [6, 20],
        "high": [0x80000014] * 2,
        "mixedhigh": [20, 0x80000014],
        "zero": [0, 0],
        "duplicate": [20, 20],
        "large": [20] * 39 + [6],
    }[kind]
    # Distinct RRsets intentionally prevent the library from minimizing TTLs
    # or removing duplicate records before the fixture reaches the wire.
    response.answer = [
        rr(name, "A", f"192.0.2.{1 if kind == 'duplicate' else index + 1}", ttl)
        for index, ttl in enumerate(ttls)
    ]
    return response.to_wire(max_size=65535)


def answer(wire, protocol="udp"):
    global COUNTS
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    question = query.question[0]
    name = question.name.to_text().lower()
    kind = dns.rdatatype.to_text(question.rdtype)
    with LOCK:
        COUNTS[f"{name}/{kind}"] += 1
        if name.startswith("tcpdrop-"):
            COUNTS[f"{protocol}:{name}/{kind}"] += 1
        generation = GENERATION
    if name.startswith("tcpdrop-"):
        if protocol == "tcp":
            return None
        response.flags |= dns.flags.TC
        return response.to_wire()
    if name == "." and kind == "NS":
        response.answer = [rr(".", "NS", "ns.root.", 300)]
        response.additional = [rr("ns.root.", "A", HOST, 300)]
    elif name == "ns.root." and kind == "A":
        response.answer = [rr(name, "A", HOST, 300)]
    elif name.endswith(ZONE):
        if name.startswith("ttl-"):
            return ttl_answer(response, name)
        if name.startswith(("servfail-", "refused-")):
            if kind == "AAAA":
                response.answer = [rr(name, "AAAA", "2001:db8::90")]
            elif generation:
                response.answer = [rr(name, "A", "192.0.2.90")]
            else:
                response.flags &= ~dns.flags.AA
                response.set_rcode(
                    dns.rcode.SERVFAIL
                    if name.startswith("servfail-")
                    else dns.rcode.REFUSED
                )
            return response.to_wire()
        if name == ZONE and kind == "NS":
            response.answer = [rr(ZONE, "NS", f"ns.{ZONE}", 300)]
            response.additional = [rr(f"ns.{ZONE}", "A", HOST, 300)]
            return response.to_wire()
        if name == ZONE and kind == "SOA":
            response.answer = [
                rr(ZONE, "SOA", f"ns.{ZONE} hostmaster.{ZONE} 1 60 60 60 6", 20)
            ]
            return response.to_wire()
        if name == f"ns.{ZONE}" and kind == "A":
            response.answer = [rr(name, "A", HOST, 300)]
            return response.to_wire()
        if name.startswith("oversized-soa-"):
            if generation:
                response.answer = [rr(name, "A", "192.0.2.99")]
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
                # Deliberately violate RFC 2308 §3 to test resolver handling.
                response.authority = [
                    rr(ZONE, "SOA", f"ns.{ZONE} hostmaster.{ZONE} 1 60 60 60 6", 20)
                ]
            return response.to_wire()
        if name.startswith("short-alias-"):
            suffix = name.removeprefix("short-alias-")
            terminal = ("new-" if generation else "old-") + suffix
            response.answer.append(rr(name, "CNAME", terminal, 2))
            if kind == "CNAME":
                return response.to_wire()
            if generation and kind == "A":
                response.answer.append(rr(terminal, "A", "192.0.2.101", 12))
            elif not generation:
                response.set_rcode(dns.rcode.NXDOMAIN)
                response.authority.append(
                    rr(ZONE, "SOA", f"ns.{ZONE} hostmaster.{ZONE} 1 60 60 60 12", 12)
                )
            else:
                response.authority.append(
                    rr(ZONE, "SOA", f"ns.{ZONE} hostmaster.{ZONE} 1 60 60 60 12", 12)
                )
            return response.to_wire()
        if name.startswith("old-"):
            response.set_rcode(dns.rcode.NXDOMAIN)
            response.authority.append(
                rr(ZONE, "SOA", f"ns.{ZONE} hostmaster.{ZONE} 1 60 60 60 12", 12)
            )
            return response.to_wire()
        if name.startswith("new-") and kind == "A":
            response.answer.append(rr(name, "A", "192.0.2.101", 12))
            return response.to_wire()
        terminal = name
        if name.startswith("alias-"):
            terminal = name.removeprefix("alias-")
            response.answer.append(rr(name, "CNAME", terminal, 30))
            if kind == "CNAME":
                return response.to_wire()
        if terminal.startswith("positive-") and kind == "A":
            response.answer.append(rr(terminal, "A", f"192.0.2.{80 + generation}"))
        elif terminal.startswith("nodata-") and kind == "AAAA":
            response.answer.append(rr(terminal, "AAAA", "2001:db8::80"))
        elif terminal.startswith("missing-") and generation:
            if kind == "A":
                response.answer.append(rr(terminal, "A", "192.0.2.99"))
            else:
                response.authority.append(
                    rr(ZONE, "SOA", f"ns.{ZONE} hostmaster.{ZONE} 1 60 60 60 6", 6)
                )
        else:
            if terminal.startswith("missing-"):
                response.set_rcode(dns.rcode.NXDOMAIN)
            # The authority emits RFC 2308's already-minimized negative TTL.
            response.authority.append(
                rr(ZONE, "SOA", f"ns.{ZONE} hostmaster.{ZONE} 1 60 60 60 6", 6)
            )
    else:
        response.authority.append(
            rr(".", "SOA", "ns.root. hostmaster.root. 1 60 60 60 6", 6)
        )
    return response.to_wire()


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        sock.sendto(answer(wire), self.client_address)


def exact(stream, count):
    value = bytearray()
    while len(value) < count:
        part = stream.recv(count - len(value))
        if not part:
            return None
        value.extend(part)
    return bytes(value)


class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        while header := exact(self.request, 2):
            wire = exact(self.request, struct.unpack("!H", header)[0])
            if wire is None:
                return
            response = answer(wire, "tcp")
            if response is None:
                return
            self.request.sendall(struct.pack("!H", len(response)) + response)


class Control(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/counts":
            self.send_error(404)
            return
        with LOCK:
            body = json.dumps(dict(COUNTS)).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        global GENERATION
        if self.path != "/advance":
            self.send_error(404)
            return
        with LOCK:
            GENERATION += 1
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    servers = (
        socketserver.ThreadingUDPServer((HOST, 53), Udp),
        socketserver.ThreadingTCPServer((HOST, 53), Tcp),
        ThreadingHTTPServer((HOST, 8053), Control),
    )
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("READY independent cache authority", flush=True)
    threading.Event().wait()

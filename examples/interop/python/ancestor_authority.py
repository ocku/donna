"""Independent observable root/TLD/leaf hierarchy with a controlled lame leaf."""

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

ROLE = os.environ["AUTHORITY_ROLE"]
HOSTS = {"root": "172.29.56.20", "tld": "172.29.56.21", "leaf": "172.29.56.22"}
ORIGINS = {"root": ".", "tld": "test.", "leaf": "example.test."}
COUNTS = Counter()
LOCK = threading.Lock()
FAILED = False


def rr(owner, kind, value, ttl=300):
    return dns.rrset.from_text(owner, ttl, "IN", kind, value)


def answer(wire, protocol):
    query = dns.message.from_wire(wire)
    reply = dns.message.make_response(query)
    name = query.question[0].name.to_text().lower()
    kind = dns.rdatatype.to_text(query.question[0].rdtype)
    with LOCK:
        COUNTS[f"{protocol}:{name}/{kind}"] += 1
        failed = FAILED
    origin = ORIGINS[ROLE]
    ns = {"root": "ns.root.", "tld": "ns.test.", "leaf": "ns.example.test."}[ROLE]
    if ROLE == "leaf" and failed:
        reply.set_rcode(dns.rcode.REFUSED)
    elif kind == "A" and name == ns:
        reply.flags |= dns.flags.AA
        reply.answer = [rr(name, "A", HOSTS[ROLE])]
    elif name == ns:
        reply.flags |= dns.flags.AA
        reply.authority = [
            rr(origin, "SOA", f"{ns} hostmaster.test. 1 60 60 60 30", 30)
        ]
    elif kind == "NS" and name == origin:
        reply.flags |= dns.flags.AA
        reply.answer = [rr(origin, "NS", ns)]
        reply.additional = [rr(ns, "A", HOSTS[ROLE])]
    elif ROLE == "leaf" or (ROLE == "tld" and name.endswith("healthy.test.")):
        reply.flags |= dns.flags.AA
        if kind == "A":
            reply.answer = [rr(name, "A", "192.0.2.80", 60)]
        else:
            reply.authority = [
                rr(origin, "SOA", f"{ns} hostmaster.test. 1 60 60 60 30", 30)
            ]
    elif ROLE == "tld" and name == "example.test." and kind == "DS":
        reply.flags |= dns.flags.AA
        reply.authority = [
            rr("test.", "SOA", "ns.test. hostmaster.test. 1 60 60 60 30", 30)
        ]
    else:
        child, target, address = (
            ("test.", "ns.test.", HOSTS["tld"])
            if ROLE == "root"
            else ("example.test.", "ns.example.test.", HOSTS["leaf"])
        )
        reply.authority = [rr(child, "NS", target)]
        reply.additional = [rr(target, "A", address)]
    return reply.to_wire()


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        sock.sendto(answer(wire, "udp"), self.client_address)


def exact(stream, count):
    result = b""
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            return None
        result += part
    return result


class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        while header := exact(self.request, 2):
            wire = exact(self.request, struct.unpack("!H", header)[0])
            if wire is None:
                return
            reply = answer(wire, "tcp")
            self.request.sendall(struct.pack("!H", len(reply)) + reply)


class Control(BaseHTTPRequestHandler):
    def do_GET(self):
        with LOCK:
            body = json.dumps(dict(COUNTS)).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        global FAILED
        with LOCK:
            FAILED = self.path == "/fail"
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


for kind, handler in (
    (socketserver.ThreadingUDPServer, Udp),
    (socketserver.ThreadingTCPServer, Tcp),
):
    server = kind(("0.0.0.0", 53), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
print("READY", ROLE, flush=True)
ThreadingHTTPServer(("0.0.0.0", 8053), Control).serve_forever()

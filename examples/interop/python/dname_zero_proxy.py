"""Forward signed parent replies and optionally set synthesized CNAME TTL to zero."""

import os
import socketserver
import struct
import threading

import dns.message
import dns.name
import dns.query
import dns.rdatatype

UPSTREAM = "172.29.53.76"
ZERO = os.environ.get("ZERO_CNAME") == "1"
OWNER = dns.name.from_text("old.test.")


def forward(wire, protocol, client):
    request = dns.message.from_wire(wire)
    print(
        f"QUERY {client} {request.question[0].name} {request.question[0].rdtype}",
        flush=True,
    )
    response = getattr(dns.query, protocol)(request, UPSTREAM, timeout=5)
    if ZERO:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME and rrset.name.is_subdomain(OWNER):
                rrset.ttl = 0
    return response.to_wire()


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        sock.sendto(forward(wire, "udp", self.client_address[0]), self.client_address)


class TCP(socketserver.StreamRequestHandler):
    def handle(self):
        header = self.rfile.read(2)
        if len(header) != 2:
            return
        size = struct.unpack("!H", header)[0]
        wire = self.rfile.read(size)
        if len(wire) != size:
            return
        result = forward(wire, "tcp", self.client_address[0])
        self.wfile.write(struct.pack("!H", len(result)) + result)


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with UDPServer(("0.0.0.0", 53), UDP) as udp, TCPServer(("0.0.0.0", 53), TCP) as tcp:
        threading.Thread(target=udp.serve_forever, daemon=True).start()
        tcp.serve_forever()

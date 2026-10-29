"""Deliberately malformed extended-RCODE DNAME authority for the lab."""

import json
import socket
import socketserver
import struct
import threading

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset


HOST = "172.29.56.20"
TARGET = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 60)) + "."


def answer(wire):
    query = dns.message.from_wire(wire)
    reply = dns.message.make_response(query)
    reply.flags |= dns.flags.AA
    question = query.question[0]
    owner = question.name.to_text().lower()
    kind = question.rdtype
    if owner == "." and kind == dns.rdatatype.NS:
        reply.answer = [dns.rrset.from_text(".", 300, "IN", "NS", "ns.root.")]
        reply.additional = [dns.rrset.from_text("ns.root.", 300, "IN", "A", HOST)]
    elif owner == "ns.root." and kind == dns.rdatatype.A:
        reply.answer = [dns.rrset.from_text(owner, 300, "IN", "A", HOST)]
    elif owner in {
        f"{case}-{proto}.{case}-{proto}.example.test."
        for case in ("valid", "bad")
        for proto in ("udp", "tcp")
    }:
        dname_owner = owner.split(".", 1)[1]
        reply.answer = [dns.rrset.from_text(dname_owner, 30, "IN", "DNAME", TARGET)]
        # RCODE 6 is YXDOMAIN. The latter deliberately has extended bits,
        # making its complete RCODE 22 instead of YXDOMAIN.
        reply.set_rcode(22 if owner.startswith("bad-") else 6)
    else:
        reply.set_rcode(dns.rcode.NXDOMAIN)
        reply.authority = [
            dns.rrset.from_text(
                ".", 30, "IN", "SOA", "ns.root. hostmaster.root. 1 60 60 3600 30"
            )
        ]
    wire = reply.to_wire()
    print(
        json.dumps(
            {
                "authority": owner,
                "query_edns": query.edns,
                "response_edns": reply.edns,
                "response_rcode": reply.rcode(),
                "wire_hex": wire.hex(),
            }
        ),
        flush=True,
    )
    return wire


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        sock.sendto(answer(packet), self.client_address)


class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        length = self.request.recv(2, socket.MSG_WAITALL)
        if len(length) != 2:
            return
        packet = self.request.recv(struct.unpack("!H", length)[0], socket.MSG_WAITALL)
        response = answer(packet)
        self.request.sendall(struct.pack("!H", len(response)) + response)


class ThreadedUdp(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadedTcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    udp = ThreadedUdp((HOST, 53), Udp)
    tcp = ThreadedTcp((HOST, 53), Tcp)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    print("READY", flush=True)
    tcp.serve_forever()

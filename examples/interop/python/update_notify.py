"""Independent RFC 2136/8945 updates and RFC 1996 notification checks.

Run `python update_notify.py updates` against the UPDATE example, then restart
that server and run `python update_notify.py updates --verify-restart`.
The notify target must be this process's address on UDP port 5401.
"""

import argparse
import base64
import socket
import time

import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update

ZONE = "example.test."
OWNER = "dynamic.example.test."
SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
KEYRING = dns.tsigkeyring.from_text({"interop-key.": SECRET})


def update():
    return dns.update.Update(
        ZONE, keyring=KEYRING, keyname="interop-key.", keyalgorithm=dns.tsig.HMAC_SHA256
    )


def exchange(request, host, port, expected=dns.rcode.NOERROR, tcp=True):
    send = dns.query.tcp if tcp else dns.query.udp
    response = send(request, host, port=port, timeout=5)
    assert response.rcode() == expected, (
        dns.rcode.to_text(response.rcode()),
        dns.rcode.to_text(expected),
    )
    if request.keyring:
        assert response.had_tsig, "authenticated UPDATE response must carry TSIG"
    return response


def address(host, port):
    response = exchange(dns.message.make_query(OWNER, "A"), host, port)
    return [
        str(item)
        for rrset in response.answer
        if rrset.rdtype == dns.rdatatype.A
        for item in rrset
    ]


def serial(host, port):
    response = exchange(dns.message.make_query(ZONE, "SOA"), host, port)
    return response.answer[0][0].serial


def drain_notifications(receiver):
    receiver.settimeout(0.05)
    try:
        while True:
            wire, peer = receiver.recvfrom(65535)
            request = dns.message.from_wire(wire)
            receiver.sendto(dns.message.make_response(request).to_wire(), peer)
    except socket.timeout:
        pass


def expect_notify(receiver, expected_serial):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        receiver.settimeout(max(0.01, deadline - time.monotonic()))
        wire, peer = receiver.recvfrom(65535)
        request = dns.message.from_wire(wire)
        assert request.opcode() == dns.opcode.NOTIFY
        assert request.flags & dns.flags.AA
        assert request.question[0].name.to_text() == ZONE
        receiver.sendto(dns.message.make_response(request).to_wire(), peer)
        if any(
            item.serial == expected_serial
            for rrset in request.answer
            if rrset.rdtype == dns.rdatatype.SOA
            for item in rrset
        ):
            return
    raise AssertionError("no NOTIFY for committed zone serial")


def run(host, port, notify_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("0.0.0.0", notify_port))
        drain_notifications(receiver)
        initial_serial = serial(host, port)
        unsigned = dns.update.Update(ZONE)
        unsigned.add(OWNER, 60, "A", "192.0.2.200")
        exchange(unsigned, host, port, dns.rcode.REFUSED)

        denied = update()
        denied.add("outside-grant", 60, "A", "192.0.2.200")
        exchange(denied, host, port, dns.rcode.REFUSED)
        denied_type = update()
        denied_type.add(OWNER, 60, "TXT", '"not-authorized"')
        exchange(denied_type, host, port, dns.rcode.REFUSED)

        add = update()
        add.absent(OWNER)
        add.add(OWNER, 60, "A", "192.0.2.200")
        exchange(add, host, port)
        assert address(host, port) == ["192.0.2.200"]
        changed_serial = serial(host, port)
        assert 0 < (changed_serial - initial_serial) % (2**32) < 2**31
        expect_notify(receiver, changed_serial)

        failed = update()
        failed.absent(OWNER)
        failed.add(OWNER, 60, "A", "192.0.2.201")
        exchange(failed, host, port, dns.rcode.YXDOMAIN)
        assert address(host, port) == ["192.0.2.200"]
        assert serial(host, port) == changed_serial

        replace = update()
        replace.present(OWNER, "A", "192.0.2.200")
        replace.delete(OWNER, "A", "192.0.2.200")
        replace.add(OWNER, 60, "A", "192.0.2.201")
        exchange(replace, host, port, tcp=False)
        assert address(host, port) == ["192.0.2.201"]
        expect_notify(receiver, serial(host, port))
        print(
            "PASS: authorized TSIG updates, ACLs, prerequisites, deletion, UDP/TCP, NOTIFY"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=5301)
    parser.add_argument("--notify-port", type=int, default=5401)
    parser.add_argument("--verify-restart", action="store_true")
    args = parser.parse_args()
    if args.verify_restart:
        assert address(args.host, args.port) == ["192.0.2.201"]
        print("PASS: acknowledged update survives server restart")
    else:
        run(args.host, args.port, args.notify_port)

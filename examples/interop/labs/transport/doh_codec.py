#!/usr/bin/env python3
"""Run independent raw HTTP/2 DoH checks using existing Docker images only."""

import argparse
import json
import time
from pathlib import Path

from support.docker import docker
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes

PREFIX = "donna-doh-codec-"
NETWORK = PREFIX + "network"
CERTS = PREFIX + "certificates"


@exclusive_laboratory
def execute(image):
    suite = SUITE
    names = [PREFIX + role for role in ("server", "probe")]
    try:
        print(
            json.dumps(
                {
                    "images": {
                        role: json.loads(docker("image", "inspect", ref, capture=True))[
                            0
                        ]["Id"]
                        for role, ref in (
                            ("donna", image),
                            ("peers", "donna-interop-peers"),
                        )
                    },
                    "harness_sha256": harness_hashes(
                        suite,
                        (
                            Path(__file__),
                            suite / "python/http_errors.py",
                            suite / "python/certificates.py",
                        ),
                    ),
                }
            ),
            flush=True,
        )
        docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
        docker("volume", "create", CERTS, capture=True)
        docker(
            "run",
            "--rm",
            "-v",
            CERTS + ":/certs",
            "donna-interop-peers",
            "python",
            "certificates.py",
            capture=True,
        )
        docker(
            "run",
            "-d",
            "--name",
            names[0],
            "--network",
            NETWORK,
            "--ip",
            "172.29.53.10",
            "-v",
            CERTS + ":/certs:ro",
            "-e",
            "TOKIO_WORKER_THREADS=2",
            image,
            "listeners",
            capture=True,
        )
        docker(
            "run",
            "-d",
            "--name",
            names[1],
            "--network",
            NETWORK,
            "-v",
            CERTS + ":/certs:ro",
            "donna-interop-peers",
            "sleep",
            "infinity",
            capture=True,
        )
        docker(
            "cp",
            str(suite / "python/http_errors.py"),
            names[1] + ":/suite/http_errors.py",
        )
        deadline = time.monotonic() + 15
        while True:
            ready = docker(
                "exec",
                names[1],
                "python",
                "-c",
                "import socket; socket.create_connection(('172.29.53.10',8443),.3).close(); print('READY')",
                capture=True,
                check=False,
            )
            if ready.strip() == "READY":
                break
            if time.monotonic() > deadline:
                raise RuntimeError(
                    "DoH listener not ready: " + docker("logs", names[0], capture=True)
                )
            time.sleep(0.1)
        print(
            docker("exec", names[1], "python", "/suite/http_errors.py", capture=True),
            flush=True,
        )
        script = """import base64,json,dns.message,dns.edns
from http_errors import request
for size in range(3):
 q=dns.message.make_query("www.example.test.","A",use_edns=0,options=[dns.edns.GenericOption(65001,b"x"*size)])
 wire=q.to_wire(); encoded=base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
 for method in ("GET","POST"):
  status,body=request(method,"/dns-query?dns="+encoded if method=="GET" else "/dns-query",wire if method=="POST" else b"",return_wire=True)
  reply=dns.message.from_wire(body)
  assert status==200 and q.is_response(reply) and reply.rcode()==0 and reply.answer
  print(json.dumps({"method":method,"wire_length_mod3":len(wire)%3,"status":status,"answer":[r.to_text() for r in reply.answer],"passed":True}))
print(json.dumps({"result":"PASS","independent_raw_wire_rows":6,"http_status_gates":7}))"""
        print(
            docker("exec", names[1], "python", "-c", script, capture=True), flush=True
        )
    finally:
        docker("rm", "-f", *names, check=False, capture=True)
        docker("network", "rm", NETWORK, check=False, capture=True)
        docker("volume", "rm", CERTS, check=False, capture=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", required=True)
    execute(parser.parse_args().donna_image)

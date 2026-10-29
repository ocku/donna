#!/usr/bin/env python3
"""One two-second QDCOUNT recheck with adjacent valid controls; no throughput load."""

import argparse
import hashlib
import json
from support.paths import SUITE
from pathlib import Path
import subprocess
import tarfile
import tempfile

from labs.authority import similar as lab
from benchmarks.diversity_compare import identity, logs, log_digest
from support.lock import exclusive_laboratory
from support.docker import docker

WORKER = r"""
import json, socket, struct, time
import dns.message
from ingress_wire import catalog, check_packet, normalized, read_exact
cases = {item["case"]: item for item in catalog()}
bad = cases["two-questions-compressed-second"]
wire = bytes.fromhex(bad["query"])
parsed = dns.message.from_wire(wire)
assert len(parsed.question) == 2
assert parsed.question[0].name == parsed.question[1].name
assert parsed.question[0].rdtype == 1 and parsed.question[1].rdtype == 28
pointer = wire.index(b"\xc0\x0c")
assert pointer > 12
print(json.dumps(dict(query_proof={"wire": wire.hex(), "header": struct.unpack("!6H", wire[:12]),
 "questions": [q.to_text() for q in parsed.question], "second_name_pointer_offset": pointer,
 "second_name_pointer_target": 12, "edns_version": parsed.edns})), flush=True)
for protocol in ("udp", "tcp"):
 for phase, case in (("before", cases["edns"]), ("qdcount-two", bad), ("after", cases["edns"])):
  query = bytes.fromhex(case["query"])
  received = bytearray()
  row = dict(protocol=protocol, phase=phase, query=query.hex(), timeout_seconds=2)
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM) as peer:
   peer.settimeout(2)
   peer.connect(("172.29.59.30", 53))
   started = time.monotonic()
   try:
    if protocol == "udp":
     assert peer.send(query) == len(query)
     response = peer.recv(65535)
    else:
     peer.sendall(len(query).to_bytes(2, "big") + query)
     prefix = read_exact(peer, 2, received)
     response = read_exact(peer, int.from_bytes(prefix, "big"), received)
    row.update(outcome="reply", response=response.hex(), normalized=normalized(response))
    assert response[:2] == query[:2]
    check_packet(case, response)
   except TimeoutError:
    row["outcome"] = "timeout"
   except (EOFError, ConnectionResetError):
    row["outcome"] = "closed"
   row["elapsed_seconds"] = time.monotonic() - started
  if protocol == "tcp": row["received_stream"] = received.hex()
  if phase != "qdcount-two": assert row["outcome"] == "reply", row
  print(json.dumps(row), flush=True)
"""


@exclusive_laboratory
def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    suite = SUITE
    lab.PREFIX = "donna-qcount-recheck-"
    lab.NETWORK, lab.VOLUME, lab.CERTS = (
        lab.PREFIX + kind for kind in ("network", "public-zone", "certificates")
    )
    lab.ROLES = {"knot": (identity("cznic/knot:3.6"), "172.29.59.30")}
    lab.WORKERS = 2
    record = dict(
        scope="One UDP/TCP QD2 recheck, each with a2-second receive bound and valid before/after control; no eventual-response or universal compliance claim",
        image=lab.ROLES["knot"][0],
        rows=[],
    )
    output = suite / ".artifacts/qcount-recheck.json"
    try:
        docker(
            "network", "create", "--subnet", "172.29.59.0/24", lab.NETWORK, capture=True
        )
        docker("volume", "create", lab.VOLUME, capture=True)
        docker(
            "run",
            "-d",
            "--name",
            lab.PREFIX + "signer",
            "--network",
            "none",
            "-v",
            lab.VOLUME + ":/work",
            "donna-interop-bind",
            "sleep",
            "infinity",
            capture=True,
        )
        docker(
            "run",
            "-d",
            "--name",
            lab.PREFIX + "probe",
            "--network",
            lab.NETWORK,
            "--entrypoint",
            "sleep",
            identity("donna-interop-diversity-client:checked-v2"),
            "infinity",
            capture=True,
        )
        with tempfile.TemporaryDirectory(prefix="donna-qcount-recheck-") as temporary:
            root = Path(temporary)
            (root / "worker.py").write_text(WORKER)
            docker("cp", str(root / "worker.py"), lab.PREFIX + "probe:/suite/worker.py")
            docker(
                "cp",
                str(suite / "python/ingress_wire.py"),
                lab.PREFIX + "probe:/suite/ingress_wire.py",
            )
            lab.put(root, "unsigned.db", (suite / "fixtures/basic/zone.db").read_text())
            lab.put(
                root,
                "knot.conf",
                "server:\n    rundir: /tmp\n    listen: 0.0.0.0@53\n    udp-workers: 2\n    tcp-workers: 2\n    background-workers: 1\n    udp-max-payload: 1232\n"
                "log:\n  - target: stderr\n    any: error\ndatabase:\n    storage: /tmp/knot-db\ntemplate:\n  - id: default\n    storage: /tmp\n    zonefile-sync: -1\n"
                "zone:\n  - domain: example.test.\n    file: /work/active.db\n    dnssec-signing: off\n",
            )
            lab.start("unsigned")
            before = logs()
            record["version"] = docker(
                "exec", lab.PREFIX + "knot", "knotd", "-V", capture=True
            )
            run = subprocess.run(
                ["docker", "exec", lab.PREFIX + "probe", "python", "/suite/worker.py"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            record.update(
                exit_code=run.returncode,
                rows=[
                    json.loads(line)
                    for line in run.stdout.splitlines()
                    if line.startswith("{")
                ],
            )
            record["raw_output"] = run.stdout
            assert run.returncode == 0, run.stdout
            assert len(record["rows"]) == 7
            assert logs() == before
            record["log_gate"] = dict(
                before=log_digest(before), after=log_digest(logs())
            )
            capsule = suite / ".artifacts/binaries/qcount-recheck.tar.gz"
            with tarfile.open(capsule, "w:gz") as archive:
                for path in root.iterdir():
                    archive.add(path, arcname=path.name)
                archive.add(Path(__file__), arcname="labs/transport/qcount_recheck.py")
                archive.add(suite / "python/ingress_wire.py", arcname="ingress_wire.py")
            record["capsule"] = dict(
                path=str(capsule),
                sha256=hashlib.sha256(capsule.read_bytes()).hexdigest(),
            )
    finally:
        lab.cleanup()
        record["cleanup"] = (
            "Only task Knot/probe/carrier containers, network and public-zone volume removed; no images built."
        )
        output.write_text(json.dumps(record, indent=2) + "\n")
    print(
        json.dumps(
            {
                "exit_code": record["exit_code"],
                "outcomes": [
                    (r["protocol"], r["phase"], r["outcome"])
                    for r in record["rows"]
                    if "outcome" in r
                ],
            }
        )
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare validating recursive DNAME chains across signed sibling zones."""

import argparse
import hashlib
import json
import subprocess
import tempfile
import time
from pathlib import Path

from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes
from support.topology import NETWORK, PREFIX, docker

from labs.dnssec import chain

OTHER = PREFIX + "chain-other"


def prepare_cross(directory, mode):
    chain.prepare(directory, 1, mode)
    docker("exec", chain.SIGNER, "mkdir", "-p", "/work/other")
    chain.ORIGINS["other"] = "other.test."
    key = None
    for flag in ("KSK", "ZSK"):
        args = [
            "exec",
            "-w",
            "/work/other",
            chain.SIGNER,
            "dnssec-keygen",
            "-q",
            "-a",
            "ECDSAP256SHA256",
        ]
        if flag == "KSK":
            args += ["-f", "KSK"]
        generated = docker(*args, "other.test.", capture=True)
        if flag == "KSK":
            key = generated
    ds = (
        docker(
            "exec",
            "-w",
            "/work/other",
            chain.SIGNER,
            "dnssec-dsfromkey",
            "-2",
            key + ".key",
            capture=True,
        )
        + "\n"
    )
    tld = docker("exec", chain.SIGNER, "cat", "/work/tld/zone.db", capture=True)
    tld += "\nother IN NS ns.other.test.\nns.other IN A 172.29.53.75\n" + ds
    chain.put(directory, "tld/zone.db", tld)
    chain.sign("tld", mode)
    docker("exec", chain.SIGNER, "cp", "/work/tld/signed.db", "/work/tld/active.db")
    fields = ds.split()
    offset = fields.index("DS") + 1
    fields[offset] = str(int(fields[offset]) ^ 1)
    chain.put(directory, "tld/zone.db", tld.replace(ds, " ".join(fields) + "\n"))
    chain.sign("tld", mode, "other-bad-ds.db")
    chain.put(directory, "tld/zone.db", tld)
    leaf = docker("exec", chain.SIGNER, "cat", "/work/leaf/zone.db", capture=True)
    leaf += (
        "\nold 120 IN DNAME dest.other.test.\nbridge 120 IN DNAME hop.other.test.\n"
        "www.dest 300 IN A 192.0.2.80\n"
    )
    other = (
        "$ORIGIN other.test.\n$TTL 300\n"
        "@ IN SOA ns.other.test. hostmaster.other.test. 1 60 60 3600 30\n"
        "@ IN NS ns.other.test.\nns IN A 172.29.53.75\n"
        "www.dest IN A 192.0.2.81\nwww.dest IN AAAA 2001:db8::81\n"
        "hop 120 IN DNAME dest.example.test.\n"
    )
    for zone, text in (("leaf", leaf), ("other", other)):
        chain.put(directory, zone + "/zone.db", text)
        chain.sign(zone, mode)
        docker(
            "exec",
            chain.SIGNER,
            "cp",
            f"/work/{zone}/signed.db",
            f"/work/{zone}/active.db",
        )
    chain.put(
        directory,
        "other.conf",
        'options { directory "/tmp"; listen-on { any; }; '
        "listen-on-v6 { none; }; recursion no; dnssec-validation no; querylog yes; };\n"
        'zone "other.test" { type primary; file "/work/other/active.db"; };\n',
    )


def run_peer(server, protocol, mode, image, bad_chain=False):
    chain.start_resolver(server, image)
    host, port = ("172.29.53.74", 5301) if server == "donna" else ("172.29.53.73", 53)
    deadline = time.monotonic() + 15
    while (
        docker(
            "exec",
            PREFIX + "probe",
            "python",
            "-c",
            f"import socket; socket.create_connection(('{host}',{port}),.3).close(); print('READY')",
            check=False,
            capture=True,
        ).strip()
        != "READY"
    ):
        if time.monotonic() >= deadline:
            raise RuntimeError("resolver did not start: " + server)
        time.sleep(0.1)
    command = [
        "docker",
        "exec",
        PREFIX + "probe",
        "python",
        "/suite/dname_cross_probe.py",
        "--server",
        server,
        "--host",
        host,
        "--port",
        str(port),
        "--protocol",
        protocol,
        "--mode",
        mode,
    ]
    if bad_chain:
        command.append("--bad-chain")
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, result.stderr, flush=True)
        raise RuntimeError("cross-zone DNAME probe failed")
    objects = [
        json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")
    ]
    rows = [row for row in objects if "case" in row]
    if len(rows) != (2 if bad_chain else 5):
        raise RuntimeError("incomplete cross-zone DNAME matrix")
    failures = []
    for row in rows:
        row["mode"] = mode
        print(json.dumps(row), flush=True)
        if not row["passed"]:
            failures.append(row)
    if not bad_chain:
        faults = [row for row in objects if "fault_tests_passed" in row]
        if len(faults) != 1 or faults[0]["fault_tests_passed"] != 5:
            failures.append(
                {
                    "server": server,
                    "protocol": protocol,
                    "mode": mode,
                    "error": "missing fault-injection checks",
                }
            )
        for row in faults:
            row["mode"] = mode
            print(json.dumps(row), flush=True)
    return failures


def cleanup():
    docker("rm", "-f", OTHER, PREFIX + "probe", check=False, capture=True)
    chain.cleanup()
    chain.ORIGINS.pop("other", None)


@exclusive_laboratory
def execute(args):
    if (
        NETWORK
        in docker("network", "ls", "--format", "{{.Name}}", capture=True).splitlines()
    ):
        raise RuntimeError(
            "ordinary laboratory network exists; finish its owning job first"
        )
    suite = SUITE
    paths = (
        Path(__file__).resolve(),
        suite / "labs/dnssec/chain.py",
        suite / "labs/dnssec/chain_fixture.py",
        suite / "python/dname_recursive_probe.py",
        suite / "python/dname_cross_probe.py",
    )
    print(
        json.dumps(
            {
                "images": {
                    "donna": docker(
                        "image",
                        "inspect",
                        args.donna_image,
                        "--format",
                        "{{.Id}}",
                        capture=True,
                    ),
                    "bind": docker(
                        "image",
                        "inspect",
                        PREFIX + "bind",
                        "--format",
                        "{{.Id}}",
                        capture=True,
                    ),
                    "probe": docker(
                        "image",
                        "inspect",
                        PREFIX + "peers",
                        "--format",
                        "{{.Id}}",
                        capture=True,
                    ),
                },
                "harness_sha256": harness_hashes(suite, paths),
                "scope": "bounded cross-zone signed recursive DNAME comparison; no timing claim",
            }
        ),
        flush=True,
    )
    failures = []
    docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
    try:
        for mode in ("nsec", "nsec3") if args.mode == "both" else (args.mode,):
            docker("volume", "create", chain.VOLUME, capture=True)
            docker(
                "run",
                "-d",
                "--name",
                PREFIX + "probe",
                "--network",
                NETWORK,
                "-v",
                chain.VOLUME + ":/work:ro",
                PREFIX + "peers",
                "sleep",
                "infinity",
                capture=True,
            )
            for filename in ("dname_recursive_probe.py", "dname_cross_probe.py"):
                docker(
                    "cp",
                    str(suite / "python" / filename),
                    PREFIX + "probe:/suite/" + filename,
                )
            with tempfile.TemporaryDirectory(prefix="donna-cross-zone-") as temporary:
                prepare_cross(Path(temporary), mode)
                public = {}
                for name, origin in chain.ORIGINS.items():
                    verification = docker(
                        "exec",
                        "-w",
                        "/work/" + name,
                        chain.SIGNER,
                        "dnssec-verify",
                        "-o",
                        origin,
                        "active.db",
                        capture=True,
                    )
                    text = docker(
                        "exec",
                        chain.SIGNER,
                        "cat",
                        f"/work/{name}/active.db",
                        capture=True,
                    )
                    public[name] = {
                        "zone": text,
                        "captured_text_sha256": hashlib.sha256(
                            text.encode()
                        ).hexdigest(),
                        "verification": verification,
                    }
                print(
                    json.dumps({"mode": mode, "public_signed_zones": public}),
                    flush=True,
                )
                chain.start_authorities()
                docker(
                    "run",
                    "-d",
                    "--name",
                    OTHER,
                    "--network",
                    NETWORK,
                    "--ip",
                    "172.29.53.75",
                    "-v",
                    chain.VOLUME + ":/work:ro",
                    PREFIX + "bind",
                    "named",
                    "-g",
                    "-n",
                    "2",
                    "-c",
                    "/work/other.conf",
                    "-u",
                    "root",
                    capture=True,
                )
                for server in chain.RESOLVERS:
                    for protocol in ("udp", "tcp"):
                        failures.extend(
                            run_peer(server, protocol, mode, args.donna_image)
                        )
                chain.stop_resolvers()
                docker(
                    "exec",
                    chain.SIGNER,
                    "cp",
                    "/work/tld/other-bad-ds.db",
                    "/work/tld/active.db",
                )
                docker("restart", PREFIX + "chain-tld", capture=True)
                bad_zone = docker(
                    "exec", chain.SIGNER, "cat", "/work/tld/active.db", capture=True
                )
                verification = docker(
                    "exec",
                    "-w",
                    "/work/tld",
                    chain.SIGNER,
                    "dnssec-verify",
                    "-o",
                    "test.",
                    "active.db",
                    capture=True,
                )
                print(
                    json.dumps(
                        {
                            "mode": mode,
                            "bad_ds_tld": bad_zone,
                            "captured_text_sha256": hashlib.sha256(
                                bad_zone.encode()
                            ).hexdigest(),
                            "zone_verification": verification,
                        }
                    ),
                    flush=True,
                )
                for server in chain.RESOLVERS:
                    for protocol in ("udp", "tcp"):
                        failures.extend(
                            run_peer(
                                server, protocol, mode, args.donna_image, bad_chain=True
                            )
                        )
                cleanup()
    finally:
        cleanup()
        docker("network", "rm", NETWORK, check=False, capture=True)
    print(
        json.dumps({"result": "FAIL" if failures else "PASS", "failures": failures}),
        flush=True,
    )
    if failures:
        raise SystemExit("cross-zone recursive DNAME gate failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", required=True)
    parser.add_argument("--mode", choices=("nsec", "nsec3", "both"), default="both")
    execute(parser.parse_args())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare secure DNAME caching across a signed-to-unsigned delegation."""

import argparse
import hashlib
import json
import tempfile
import time
from pathlib import Path

from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes
from support.topology import NETWORK, PREFIX, docker

from labs.dnssec import chain, insecure_delegation

PROXY = PREFIX + "dname-mixed-proxy"


def probe(role, protocol, owner, address, mode):
    host, port = ("172.29.53.73", 53) if role == "bind" else ("172.29.53.74", 5301)
    output = docker(
        "exec",
        PREFIX + "probe",
        "python",
        "/suite/dname_mixed_probe.py",
        host,
        str(port),
        protocol,
        owner,
        address,
        mode,
        capture=True,
    )
    rows = [json.loads(line) for line in output.splitlines()]
    assert len(rows) == 2 and rows[0].get("fault_tests_passed") == 2
    result = rows[1]
    result["parent_denial"] = rows[0]
    return result


def wait_ready(role):
    host, port = ("172.29.53.73", 53) if role == "bind" else ("172.29.53.74", 5301)
    deadline = time.monotonic() + 20
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
            raise RuntimeError(f"resolver did not start: {role}")
        time.sleep(0.1)


def count(log, source, owner):
    return sum(line.startswith(f"QUERY {source} {owner} ") for line in log.splitlines())


def verify_zero_authority():
    deadline = time.monotonic() + 20
    while True:
        result = docker(
            "exec",
            PREFIX + "probe",
            "python",
            "-c",
            "import dns.message,dns.query,dns.rdatatype; "
            "q=dns.message.make_query('first.old.test.','A',want_dnssec=True); "
            "results=[dns.query.udp(q,'172.29.53.71',timeout=1),dns.query.tcp(q,'172.29.53.71',timeout=1)]; "
            "answers=[[rr for rr in r.answer if rr.rdtype==dns.rdatatype.CNAME] for r in results]; "
            "assert all(len(a)==1 and a[0].ttl==0 for a in answers); print('OK')",
            check=False,
            capture=True,
        )
        if result == "OK":
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "proxy did not send zero-TTL synthesized CNAME: " + result
            )
        time.sleep(0.1)


@exclusive_laboratory
def execute(args):
    suite = SUITE
    files = [
        Path(__file__).resolve(),
        suite / "labs/dnssec/chain.py",
        suite / "labs/dnssec/chain_fixture.py",
        suite / "labs/dnssec/insecure_delegation.py",
        *(
            suite / "python" / name
            for name in (
                "dname_mixed_probe.py",
                "dname_zero_proxy.py",
                "insecure_probe.py",
                "dname_recursive_probe.py",
            )
        ),
    ]
    result = {
        "images": {
            role: docker("image", "inspect", image, "--format", "{{.Id}}", capture=True)
            for role, image in (
                ("baseline", args.baseline),
                ("candidate", args.candidate),
                ("bind", PREFIX + "bind"),
                ("probe", PREFIX + "peers"),
            )
        },
        "harness_sha256": harness_hashes(suite, files),
        "rows": [],
        "scope": "secure parent DNAME to independently proved unsigned child; zero-CNAME proxy",
    }
    docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
    try:
        for mode in ("nsec", "nsec3"):
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
            for name in (
                "dname_mixed_probe.py",
                "insecure_probe.py",
                "dname_recursive_probe.py",
            ):
                docker(
                    "cp", str(suite / "python" / name), PREFIX + "probe:/suite/" + name
                )
            with tempfile.TemporaryDirectory(prefix="donna-dname-mixed-") as temp:
                directory = Path(temp)
                insecure_delegation.prepare(directory, mode)
                tld = docker(
                    "exec", chain.SIGNER, "cat", "/work/tld/zone.db", capture=True
                )
                chain.put(
                    directory, "tld/zone.db", tld + "\nold 30 IN DNAME example.test.\n"
                )
                chain.sign("tld", mode)
                docker(
                    "exec",
                    chain.SIGNER,
                    "cp",
                    "/work/tld/signed.db",
                    "/work/tld/active.db",
                )
                leaf = docker(
                    "exec", chain.SIGNER, "cat", "/work/leaf/active.db", capture=True
                )
                chain.put(
                    directory,
                    "leaf/active.db",
                    leaf + "\nfirst IN A 192.0.2.1\nsecond IN A 192.0.2.2\n",
                )
                chain.put(
                    directory,
                    "dname_zero_proxy.py",
                    (suite / "python/dname_zero_proxy.py").read_text(),
                )
                fixtures = {}
                for name in ("root", "tld", "leaf"):
                    text = docker(
                        "exec",
                        chain.SIGNER,
                        "cat",
                        f"/work/{name}/active.db",
                        capture=True,
                    )
                    fixtures[name] = {
                        "zone": text,
                        "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    }
                result.setdefault("fixtures", []).append(
                    {
                        "mode": mode,
                        "zones": fixtures,
                        "anchors": docker(
                            "exec",
                            chain.SIGNER,
                            "cat",
                            "/work/anchors.zone",
                            capture=True,
                        ),
                    }
                )
                chain.start_authorities()
                docker("rm", "-f", PREFIX + "chain-tld", capture=True)
                docker(
                    "run",
                    "-d",
                    "--name",
                    PREFIX + "chain-tld",
                    "--network",
                    NETWORK,
                    "--ip",
                    "172.29.53.76",
                    "-v",
                    chain.VOLUME + ":/work:ro",
                    PREFIX + "bind",
                    "named",
                    "-g",
                    "-n",
                    "2",
                    "-c",
                    "/work/tld.conf",
                    "-u",
                    "root",
                    capture=True,
                )
                for zero in (False, True):
                    docker("rm", "-f", PROXY, check=False, capture=True)
                    docker(
                        "run",
                        "-d",
                        "--name",
                        PROXY,
                        "--network",
                        NETWORK,
                        "--ip",
                        "172.29.53.71",
                        "-e",
                        f"ZERO_CNAME={int(zero)}",
                        "-v",
                        chain.VOLUME + ":/work:ro",
                        PREFIX + "peers",
                        "python",
                        "/work/dname_zero_proxy.py",
                        capture=True,
                    )
                    if zero:
                        verify_zero_authority()
                    for role, image in (
                        ("baseline", args.baseline),
                        ("candidate", args.candidate),
                        ("bind", PREFIX + "bind"),
                    ):
                        for protocol in ("udp", "tcp"):
                            chain.start_resolver(
                                "bind" if role == "bind" else "donna", image
                            )
                            wait_ready(role)
                            source = (
                                "172.29.53.73" if role == "bind" else "172.29.53.74"
                            )
                            before = docker("logs", PROXY, capture=True)
                            first = probe(
                                role, protocol, "first.old.test.", "192.0.2.1", mode
                            )
                            after_first = docker("logs", PROXY, capture=True)
                            second = probe(
                                role, protocol, "second.old.test.", "192.0.2.2", mode
                            )
                            after_second = docker("logs", PROXY, capture=True)
                            first_count = count(
                                after_first, source, "first.old.test."
                            ) - count(before, source, "first.old.test.")
                            second_count = count(
                                after_second, source, "second.old.test."
                            ) - count(after_first, source, "second.old.test.")
                            assert first_count >= 1, "missing first authoritative query"
                            if role == "candidate":
                                assert second_count == 0, (
                                    "candidate did not reuse authenticated DNAME"
                                )
                            if role == "baseline":
                                assert second_count >= 1, (
                                    "baseline unexpectedly reused DNAME"
                                )
                            # BIND can reconstruct the synthesized alias from
                            # its DNAME instead of forwarding upstream TTL 0.
                            if zero and role != "bind":
                                assert first["cname_ttl"] == 0, (
                                    "proxy did not deliver zero TTL"
                                )
                            row = {
                                "role": role,
                                "protocol": protocol,
                                "mode": mode,
                                "zero_cname": zero,
                                "first": first,
                                "second": second,
                                "first_queries": first_count,
                                "second_queries": second_count,
                            }
                            result["rows"].append(row)
                            print(json.dumps(row), flush=True)
                            chain.stop_resolvers()
                    docker("rm", "-f", PROXY, capture=True)
                docker("rm", "-f", PREFIX + "probe", check=False, capture=True)
                chain.cleanup()
    finally:
        docker("rm", "-f", PROXY, PREFIX + "probe", check=False, capture=True)
        chain.cleanup()
        docker("network", "rm", NETWORK, check=False, capture=True)
    result["result"] = "PASS"
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--baseline",
        required=True,
        help="explicit CLI-capable comparison control image",
    )
    parser.add_argument("--output", required=True)
    execute(parser.parse_args())

#!/usr/bin/env python3
"""Compare cached, signed DNAME reuse and expiry across independent resolvers."""

import argparse
import hashlib
import json
import re
import tempfile
import time
from pathlib import Path

from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes
from support.topology import NETWORK, PREFIX, docker

from labs.dnssec import chain


def query(role, protocol, owner, destination, address, via_alias=None):
    host, port = ("172.29.53.73", 53) if role == "bind" else ("172.29.53.74", 5301)
    command = [
        "exec",
        PREFIX + "probe",
        "python",
        "/suite/dname_cache_probe.py",
        host,
        str(port),
        protocol,
        owner,
        destination,
        address,
    ]
    if via_alias:
        command += ["--via-alias", via_alias]
    output = docker(*command, capture=True)
    return json.loads(output)


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


def leaf_counts(source, log):
    names = (
        "first.old.example.test",
        "second.old.example.test",
        "third.old.example.test",
    )
    return {
        name: sum(
            1
            for line in log.splitlines()
            if source in line
            and re.search(r"query: " + re.escape(name) + r"\.? IN A\b", line)
        )
        for name in names
    }


def verify_new_authority():
    output = docker(
        "exec",
        PREFIX + "probe",
        "python",
        "-c",
        "import dns.message,dns.query,dns.rdatatype; "
        "q=dns.message.make_query('old.example.test.','DNAME',want_dnssec=True); "
        "r=dns.query.udp(q,'172.29.53.72',timeout=5); "
        "a=[x for x in r.answer if x.rdtype==dns.rdatatype.DNAME]; "
        "assert len(a)==1 and a[0][0].target.to_text()=='dest2.example.test.'; print('OK')",
        capture=True,
    )
    if output != "OK":
        raise RuntimeError("authoritative replacement not active")


@exclusive_laboratory
def execute(args):
    if (
        NETWORK
        in docker("network", "ls", "--format", "{{.Name}}", capture=True).splitlines()
    ):
        raise RuntimeError("ordinary laboratory network exists")
    suite = SUITE
    files = [
        Path(__file__).resolve(),
        suite / "labs/dnssec/chain.py",
        suite / "labs/dnssec/chain_fixture.py",
        suite / "python/dname_cache_probe.py",
        suite / "python/dname_recursive_probe.py",
    ]
    result = {
        "images": {
            name: docker("image", "inspect", image, "--format", "{{.Id}}", capture=True)
            for name, image in (
                ("baseline", args.baseline),
                ("candidate", args.candidate),
                ("bind", PREFIX + "bind"),
                ("probe", PREFIX + "peers"),
            )
        },
        "harness_sha256": harness_hashes(suite, files),
        "rows": [],
        "scope": "signed DNAME caching and expiry; no throughput claim",
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
            for filename in ("dname_cache_probe.py", "dname_recursive_probe.py"):
                docker(
                    "cp",
                    str(suite / "python" / filename),
                    PREFIX + "probe:/suite/" + filename,
                )
            with tempfile.TemporaryDirectory(prefix="donna-dname-cache-") as temporary:
                directory = Path(temporary)
                chain.prepare(directory, 1, mode)
                tld = docker(
                    "exec", chain.SIGNER, "cat", "/work/tld/zone.db", capture=True
                )
                chain.put(
                    directory,
                    "tld/zone.db",
                    tld + "\nalias 300 IN CNAME second.old.example.test.\n",
                )
                chain.sign("tld", mode)
                docker(
                    "exec",
                    chain.SIGNER,
                    "cp",
                    "/work/tld/signed.db",
                    "/work/tld/active.db",
                )
                public = {}
                for zone, origin in chain.ORIGINS.items():
                    text = docker(
                        "exec",
                        chain.SIGNER,
                        "cat",
                        f"/work/{zone}/active.db",
                        capture=True,
                    )
                    public[zone] = {
                        "origin": origin,
                        "zone": text,
                        "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    }
                anchors = docker(
                    "exec", chain.SIGNER, "cat", "/work/anchors.zone", capture=True
                )
                result.setdefault("trust_fixtures", []).append(
                    {
                        "mode": mode,
                        "zones": public,
                        "anchors": anchors,
                        "anchors_sha256": hashlib.sha256(anchors.encode()).hexdigest(),
                    }
                )
                leaf = docker(
                    "exec", chain.SIGNER, "cat", "/work/leaf/zone.db", capture=True
                )
                records = (
                    "\nold 12 IN DNAME DESTINATION.example.test.\n"
                    "first.dest1 300 IN A 192.0.2.1\nsecond.dest1 300 IN A 192.0.2.2\n"
                    "second.dest2 300 IN A 192.0.2.22\nthird.dest2 300 IN A 192.0.2.3\n"
                )
                for index, dest in ((1, "dest1"), (2, "dest2")):
                    chain.put(
                        directory,
                        "leaf/zone.db",
                        leaf + records.replace("DESTINATION", dest),
                    )
                    chain.sign("leaf", mode, f"variant-{index}.db")
                    verification = docker(
                        "exec",
                        "-w",
                        "/work/leaf",
                        chain.SIGNER,
                        "dnssec-verify",
                        "-o",
                        "example.test.",
                        f"variant-{index}.db",
                        capture=True,
                    )
                    zone = docker(
                        "exec",
                        chain.SIGNER,
                        "cat",
                        f"/work/leaf/variant-{index}.db",
                        capture=True,
                    )
                    result.setdefault("fixtures", []).append(
                        {
                            "mode": mode,
                            "variant": index,
                            "zone": zone,
                            "sha256": hashlib.sha256(zone.encode()).hexdigest(),
                            "verification": verification,
                        }
                    )
                docker(
                    "exec",
                    chain.SIGNER,
                    "cp",
                    "/work/leaf/variant-1.db",
                    "/work/leaf/active.db",
                )
                chain.start_authorities()
                for role, image in (
                    ("baseline", args.baseline),
                    ("candidate", args.candidate),
                    ("bind", PREFIX + "bind"),
                ):
                    for protocol in ("udp", "tcp"):
                        docker(
                            "exec",
                            chain.SIGNER,
                            "cp",
                            "/work/leaf/variant-1.db",
                            "/work/leaf/active.db",
                        )
                        docker("restart", PREFIX + "chain-leaf", capture=True)
                        chain.start_resolver(
                            "bind" if role == "bind" else "donna", image
                        )
                        wait_ready(role)
                        source = "172.29.53.73" if role == "bind" else "172.29.53.74"
                        before = leaf_counts(
                            source, docker("logs", PREFIX + "chain-leaf", capture=True)
                        )
                        first = query(
                            role,
                            protocol,
                            "first.old.example.test.",
                            "dest1.example.test.",
                            "192.0.2.1",
                        )
                        started = time.monotonic()
                        docker(
                            "exec",
                            chain.SIGNER,
                            "cp",
                            "/work/leaf/variant-2.db",
                            "/work/leaf/active.db",
                        )
                        docker("restart", PREFIX + "chain-leaf", capture=True)
                        verify_new_authority()
                        expected = (
                            "dest2.example.test."
                            if role == "baseline"
                            else ("either" if role == "bind" else "dest1.example.test.")
                        )
                        expected_address = (
                            "192.0.2.22" if role == "baseline" else "192.0.2.2"
                        )
                        second = query(
                            role,
                            protocol,
                            "second.old.example.test.",
                            expected,
                            expected_address,
                        )
                        after_second = leaf_counts(
                            source, docker("logs", PREFIX + "chain-leaf", capture=True)
                        )
                        alias = query(
                            role,
                            protocol,
                            "second.old.example.test.",
                            expected,
                            expected_address,
                            via_alias="alias.test.",
                        )
                        after_alias = leaf_counts(
                            source, docker("logs", PREFIX + "chain-leaf", capture=True)
                        )
                        alias_old_queries = (
                            after_alias["second.old.example.test"]
                            - after_second["second.old.example.test"]
                        )
                        if role == "candidate" and alias_old_queries != 0:
                            raise RuntimeError(
                                "cached DNAME was not reused after the network CNAME"
                            )
                        elapsed = time.monotonic() - started
                        if elapsed >= first["dname_ttl"]:
                            raise RuntimeError(
                                f"fixture transition took {elapsed:.2f}s after response TTL {first['dname_ttl']}"
                            )
                        time.sleep(max(0, 13.5 - (time.monotonic() - started)))
                        third = query(
                            role,
                            protocol,
                            "third.old.example.test.",
                            "dest2.example.test.",
                            "192.0.2.3",
                        )
                        log = docker("logs", PREFIX + "chain-leaf", capture=True)
                        after = leaf_counts(source, log)
                        counts = {name: after[name] - before[name] for name in before}
                        if (
                            counts["first.old.example.test"] < 1
                            or counts["third.old.example.test"] < 1
                        ):
                            raise RuntimeError(
                                f"missing expected authoritative query: {counts}"
                            )
                        if (
                            role == "candidate"
                            and counts["second.old.example.test"] != 0
                        ):
                            raise RuntimeError(
                                f"candidate did not avoid the old-owner query: {counts}"
                            )
                        if role == "baseline" and counts["second.old.example.test"] < 1:
                            raise RuntimeError(
                                f"baseline unexpectedly reused cached DNAME: {counts}"
                            )
                        result["rows"].append(
                            {
                                "role": role,
                                "protocol": protocol,
                                "mode": mode,
                                "first": first,
                                "second": second,
                                "alias": alias,
                                "third": third,
                                "transition_seconds": elapsed,
                                "alias_old_queries": alias_old_queries,
                                "leaf_log_counts": counts,
                            }
                        )
                        print(json.dumps(result["rows"][-1]), flush=True)
                        chain.stop_resolvers()
                chain.cleanup()
                docker("rm", "-f", PREFIX + "probe", check=False, capture=True)
    finally:
        chain.cleanup()
        docker("rm", "-f", PREFIX + "probe", check=False, capture=True)
        docker("network", "rm", NETWORK, check=False, capture=True)
    result["result"] = "PASS"
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--baseline",
        required=True,
        help="explicit CLI-capable comparison control image",
    )
    parser.add_argument("--output", required=True)
    execute(parser.parse_args())


if __name__ == "__main__":
    main()

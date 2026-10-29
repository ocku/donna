#!/usr/bin/env python3
"""Compare warm and cold recursive UDP service in the isolated BIND hierarchy."""

import argparse
import hashlib
import json
import platform
import subprocess
import tempfile
from pathlib import Path

from support.daemon import create_recursive
from support.lock import exclusive_laboratory
from support.paths import ROOT, SUITE
from support.provenance import harness_hashes
from support.topology import NETWORK, PREFIX, docker

PEER_IMAGE = "donna-recursive-perf-bind:local"
SERVERS = {
    "donna": PREFIX + "recursive-perf-donna",
    "bind": PREFIX + "recursive-perf-bind",
    "baseline": PREFIX + "recursive-perf-baseline",
}
AUTHORITIES = (PREFIX + "root", PREFIX + "tld", PREFIX + "bind")
CLIENT_IMAGE = PREFIX + "cache-client"


def cpu(container):
    text = docker("exec", container, "cat", "/sys/fs/cgroup/cpu.stat", capture=True)
    return (
        int(dict(line.split() for line in text.splitlines())["usage_usec"]) / 1_000_000
    )


def rows(output):
    return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def check_image_files(image, files):
    """Ensure the retained images actually contain the fixtures we hash."""
    output = docker(
        "run",
        "--rm",
        "--entrypoint",
        "sha256sum",
        image,
        *(target for _, target in files),
        capture=True,
    )
    recorded = {}
    for line in output.splitlines():
        digest, target = line.split(maxsplit=1)
        recorded[target] = digest
    for source, target in files:
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        if recorded.get(target) != expected:
            raise RuntimeError(f"image fixture differs from worktree: {image} {target}")
    return recorded


def start_resolver(role, image):
    if role == "bind":
        docker(
            "run",
            "-d",
            "--name",
            SERVERS[role],
            "--network",
            NETWORK,
            "--ip",
            "172.29.53.50",
            PEER_IMAGE,
            capture=True,
        )
    elif role == "baseline":
        # Historical comparison images predate the shipped CLI.
        address = "172.29.53.52"
        docker(
            "run",
            "-d",
            "--name",
            SERVERS[role],
            "--network",
            NETWORK,
            "--ip",
            address,
            "-e",
            "LISTEN_HOST=" + address,
            "-e",
            "ROOT_SERVER=172.29.53.22:53",
            "-e",
            "TOKIO_WORKER_THREADS=2",
            image,
            "recursive",
            capture=True,
        )
    else:
        create_recursive(
            SERVERS[role],
            image,
            NETWORK,
            "172.29.53.51",
            "172.29.53.22:53",
            "172.29.53.0/24",
        )


def stop_resolvers():
    docker("rm", "-f", *SERVERS.values(), check=False, capture=True)


def verify_answers(role):
    """Check representative actual data as well as the load client's shape gates."""
    host, port = {
        "donna": ("172.29.53.51", 5301),
        "baseline": ("172.29.53.52", 5301),
        "bind": ("172.29.53.50", 53),
    }[role]
    program = """import dns.message,dns.query,dns.flags,dns.rcode,dns.rdatatype,sys,socket,time
host,port=sys.argv[1],int(sys.argv[2])
deadline=time.monotonic()+15
while True:
 try:
  with socket.create_connection((host,port),timeout=.2): break
 except OSError:
  if time.monotonic()>=deadline: raise
  time.sleep(.05)
def query(name,typ):
 q=dns.message.make_query(name,typ,use_edns=0,payload=1232)
 r=dns.query.udp(q,host,port=port,timeout=5)
 assert q.is_response(r) and r.flags & dns.flags.RA and not r.flags & dns.flags.TC
 return r
r=query('cache-0.wild.example.test.','TXT')
assert r.rcode()==0 and any(x.rdtype==dns.rdatatype.TXT and x[0].strings==(b'wildcard',) for x in r.answer),r.to_text()
r=query('cache-missing-0.example.test.','A')
assert r.rcode()==dns.rcode.NXDOMAIN and not r.answer and any(x.rdtype==dns.rdatatype.SOA for x in r.authority),r.to_text()
r=query('alias.example.test.','A')
assert r.rcode()==0 and any(x.rdtype==dns.rdatatype.CNAME and x[0].target.to_text()=='www.example.test.' for x in r.answer),r.to_text()
assert any(x.rdtype==dns.rdatatype.A and x[0].address=='192.0.2.80' for x in r.answer),r.to_text()
print('PASS')"""
    output = docker(
        "run",
        "--rm",
        "--network",
        NETWORK,
        "--entrypoint",
        "python",
        CLIENT_IMAGE,
        "-c",
        program,
        host,
        str(port),
        capture=True,
    )
    if output.strip() != "PASS":
        raise RuntimeError("answer verification failed: " + output)
    return {
        "server": role,
        "check": "wildcard TXT, NXDOMAIN SOA, CNAME and target A",
        "result": "PASS",
    }


def warm(args, result):
    roles = ("donna", "baseline", "bind") if args.baseline_image else ("donna", "bind")
    for role in roles:
        start_resolver(
            role, args.baseline_image if role == "baseline" else args.donna_image
        )
    for role in roles:
        result["answer_checks"].append(verify_answers(role))
    for workload in ("positive", "negative", "cname"):
        for repeat in range(args.repeats):
            if len(roles) == 3:
                order = roles[repeat % 3 :] + roles[: repeat % 3]
            else:
                order = roles if repeat % 2 == 0 else tuple(reversed(roles))
            for role in order:
                before = cpu(SERVERS[role])
                client_role = "donna" if role == "baseline" else role
                client_host = "172.29.53.52" if role == "baseline" else "172.29.53.51"
                output = docker(
                    "run",
                    "--rm",
                    "--network",
                    NETWORK,
                    CLIENT_IMAGE,
                    "--server",
                    client_role,
                    "--donna-host",
                    client_host,
                    "--workload",
                    workload,
                    "--population",
                    str(args.population),
                    "--repeats",
                    "1",
                    "--repeat-offset",
                    str(repeat),
                    "--load-seconds",
                    str(args.seconds),
                    "--query-format",
                    "edns",
                    capture=True,
                )
                elapsed_cpu = cpu(SERVERS[role]) - before
                measured = rows(output)
                if len(measured) != 1 or measured[0].get("server") != client_role:
                    raise RuntimeError("invalid warm result: " + output)
                measured[0]["server"] = role
                measured[0]["server_cgroup_cpu_seconds_with_preflight"] = elapsed_cpu
                result["warm"].extend(measured)
                print(json.dumps(measured[0]), flush=True)
                if args.no_python_latency:
                    continue
                # Python timing includes parsing and scheduling overhead, equally for both peers.
                output = docker(
                    "run",
                    "--rm",
                    "--network",
                    NETWORK,
                    CLIENT_IMAGE,
                    "--server",
                    client_role,
                    "--donna-host",
                    client_host,
                    "--workload",
                    workload,
                    "--population",
                    str(args.population),
                    "--repeats",
                    "1",
                    "--queries",
                    str(args.latency_queries),
                    "--query-format",
                    "edns",
                    capture=True,
                )
                latency = rows(output)
                if len(latency) != 2 or {row["concurrency"] for row in latency} != {
                    1,
                    32,
                }:
                    raise RuntimeError("invalid latency result: " + output)
                for row in latency:
                    row["server"] = role
                    row["repeat"] = repeat
                    result["latency"].append(row)
                    print(json.dumps(row), flush=True)
    stop_resolvers()


def cold(args, result):
    for workload in ("positive", "negative", "cname"):
        for repeat in range(args.repeats):
            for role in ("donna", "bind") if repeat % 2 == 0 else ("bind", "donna"):
                start_resolver(role, args.donna_image)
                try:
                    before = cpu(SERVERS[role])
                    output = docker(
                        "run",
                        "--rm",
                        "--network",
                        NETWORK,
                        "--entrypoint",
                        "python",
                        CLIENT_IMAGE,
                        "/suite/cold_load.py",
                        "--server",
                        role,
                        "--workload",
                        workload,
                        "--repeat",
                        str(repeat),
                        "--population",
                        str(args.population),
                        capture=True,
                    )
                    elapsed_cpu = cpu(SERVERS[role]) - before
                    measured = rows(output)
                    expected = 1 if workload == "cname" else 4
                    if len(measured) != expected:
                        raise RuntimeError("invalid cold result: " + output)
                    result["cold"].append(
                        {
                            "server": role,
                            "workload": workload,
                            "repeat": repeat,
                            "server_cgroup_cpu_seconds_with_verification": elapsed_cpu,
                            "rows": measured,
                        }
                    )
                    print(json.dumps(result["cold"][-1]), flush=True)
                finally:
                    stop_resolvers()


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--baseline-image", help="include a second Donna build in the warm comparison"
    )
    parser.add_argument("--warm-only", action="store_true")
    parser.add_argument("--no-python-latency", action="store_true")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=3)
    parser.add_argument("--population", type=int, default=1024)
    parser.add_argument("--latency-queries", type=int, default=2000)
    args = parser.parse_args()
    if (
        args.repeats < 1
        or args.seconds < 1
        or not 1 <= args.population <= 2048
        or args.latency_queries < 32
    ):
        parser.error(
            "positive repeats and seconds, population 1..2048 and at least 32 latency queries required"
        )
    if args.baseline_image and not args.warm_only:
        parser.error("a second Donna build currently requires --warm-only")
    if (
        NETWORK
        in docker("network", "ls", "--format", "{{.Name}}", capture=True).splitlines()
    ):
        raise RuntimeError("the ordinary laboratory network already exists")
    if (
        subprocess.run(
            ["docker", "image", "inspect", PEER_IMAGE],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    ):
        raise RuntimeError("temporary peer image tag already exists")
    paths = [
        Path(__file__),
        SUITE / "python/cache_network.py",
        SUITE / "python/cache_load.py",
        SUITE / "python/cold_load.py",
        SUITE / "fixtures/basic/zone.db",
        SUITE / "fixtures/hierarchy/root.db",
        SUITE / "fixtures/hierarchy/tld.db",
        SUITE / "fixtures/cache/reference.conf",
        SUITE / "fixtures/cache/root.hints",
    ]
    result = {
        "scope": "unsigned UDP recursion; EDNS; isolated root/TLD/authority; two workers; not DNSSEC or production-network performance",
        "images": {
            name: docker("image", "inspect", image, "--format", "{{.Id}}", capture=True)
            for name, image in (
                ("donna", args.donna_image),
                ("bind", PREFIX + "bind"),
                ("client", CLIENT_IMAGE),
            )
        },
        "harness_sha256": harness_hashes(ROOT, paths),
        "platform": platform.platform(),
        "docker_version": docker(
            "version", "--format", "{{.Server.Version}}", capture=True
        ),
        "configuration": vars(args),
        "answer_checks": [],
        "warm": [],
        "latency": [],
        "cold": [],
    }
    if args.baseline_image:
        result["images"]["baseline"] = docker(
            "image", "inspect", args.baseline_image, "--format", "{{.Id}}", capture=True
        )
    result["image_fixture_sha256"] = {
        "bind": check_image_files(
            PREFIX + "bind",
            [
                (SUITE / "fixtures/basic/zone.db", "/suite/fixtures/basic/zone.db"),
                (
                    SUITE / "fixtures/hierarchy/root.db",
                    "/suite/fixtures/hierarchy/root.db",
                ),
                (
                    SUITE / "fixtures/hierarchy/tld.db",
                    "/suite/fixtures/hierarchy/tld.db",
                ),
            ],
        ),
        "client": check_image_files(
            CLIENT_IMAGE,
            [
                (SUITE / "python" / name, "/suite/" + name)
                for name in ("cache_network.py", "cache_load.py", "cold_load.py")
            ],
        ),
    }
    try:
        with tempfile.TemporaryDirectory(prefix="donna-recursive-perf-") as directory:
            recipe = Path(directory) / "Dockerfile"
            recipe.write_text(
                "FROM donna-interop-bind:latest\n"
                "COPY examples/interop/fixtures/cache/reference.conf /suite/cache-reference.conf\n"
                "COPY examples/interop/fixtures/cache/root.hints /suite/cache-root.hints\n"
                'CMD ["named", "-g", "-n", "2", "-c", "/suite/cache-reference.conf", "-u", "root"]\n'
            )
            subprocess.run(
                ["docker", "build", "-t", PEER_IMAGE, "-f", str(recipe), "."],
                cwd=ROOT,
                check=True,
            )
        result["peer_image"] = docker(
            "image", "inspect", PEER_IMAGE, "--format", "{{.Id}}", capture=True
        )
        docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
        for service, address, config in (
            ("root", "172.29.53.22", "root.conf"),
            ("tld", "172.29.53.21", "tld.conf"),
            ("bind", "172.29.53.20", "named.conf"),
        ):
            docker(
                "run",
                "-d",
                "--name",
                PREFIX + service,
                "--network",
                NETWORK,
                "--ip",
                address,
                PREFIX + "bind",
                "named",
                "-g",
                "-n",
                "2",
                "-c",
                "/suite/fixtures/basic/named.conf"
                if config == "named.conf"
                else "/suite/fixtures/hierarchy/" + config,
                "-u",
                "root",
                capture=True,
            )
        warm(args, result)
        if not args.warm_only:
            cold(args, result)
        result["result"] = "PASS"
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    finally:
        stop_resolvers()
        docker("rm", "-f", *AUTHORITIES, check=False, capture=True)
        docker("network", "rm", NETWORK, check=False, capture=True)
        docker("image", "rm", PEER_IMAGE, check=False, capture=True)


if __name__ == "__main__":
    main()

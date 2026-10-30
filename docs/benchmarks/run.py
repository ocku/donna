"""Reproduce the CLI, authority, and unsigned iterative-resolver documentation tables."""

import argparse
import datetime
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples/interop"))
from support.lock import laboratory_lock
from support.recursive_peers import configuration

PREFIX = "donna-documentation-"
NETWORK = PREFIX + "network"
SUBNET = "172.30.93."
CLIENT = PREFIX + "client"
AUTHORITY_ROLES = ["donna", "bind", "knot", "hickory"]
RECURSIVE_ROLES = ["donna", "bind", "kresd", "hickory", "unbound"]


def run(*args):
    return subprocess.check_output(
        ["docker", *args], text=True, stderr=subprocess.PIPE
    ).strip()


def identity(image):
    return json.loads(run("image", "inspect", image))[0]["Id"]


def container_limits(name):
    settings = json.loads(run("inspect", "--format", "{{json .HostConfig}}", name))
    return {"nano_cpus": settings["NanoCpus"], "memory_bytes": settings["Memory"]}


def wait(address):
    # Readiness uses TCP only, preserving a cold DNS cache for the first query.
    program = (
        "import socket,time\n"
        "for i in range(200):\n"
        " try: socket.create_connection(('" + address + "',53),.1).close(); break\n"
        " except OSError: time.sleep(.05)\n"
        "else: raise RuntimeError('not ready')"
    )
    run("exec", CLIENT, "python", "-c", program)


def worker(mode, address, *args):
    return json.loads(
        run(
            "exec",
            CLIENT,
            "python",
            "/suite/documentation_worker.py",
            mode,
            address,
            *args,
        )
    )


def remove(name):
    subprocess.run(
        ["docker", "rm", "-fv", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--donna-image", default="donna-docs:local")
    p.add_argument("--client-image", default="donna-docs-client:local")
    p.add_argument("--seconds", type=int, default=3)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--cold-repeats", type=int, default=5)
    p.add_argument("--cpus", type=int, default=4, help="CPU quota per container")
    p.add_argument("--memory", default="4g", help="Docker memory limit per container")
    p.add_argument("--workers", type=int, default=4, help="Workers per server")
    p.add_argument(
        "--phases",
        nargs="+",
        choices=("cli", "authority", "recursive"),
        default=["cli", "authority", "recursive"],
    )
    p.add_argument(
        "--output",
        type=Path,
        default=ROOT / "examples/interop/.artifacts/documentation.json",
    )
    args = p.parse_args()
    if min(args.seconds, args.repeats, args.cold_repeats, args.cpus, args.workers) < 1:
        p.error("durations, repeat counts, CPU quotas and worker counts must be positive")
    limits = ["--cpus", str(args.cpus), "--memory", args.memory]
    images = {
        "donna": args.donna_image,
        "bind": "donna-interop-bind",
        "knot": "cznic/knot:3.6",
        "hickory": "donna-interop-hickory:0.26.3",
        "kresd": "donna-interop-knot-resolver:6.5.1",
        "unbound": "donna-interop-unbound",
        "client": args.client_image,
    }
    images = {role: identity(image) for role, image in images.items()}
    sources = [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    for directory in ("src", "crates", "vendor", "config", "docs/benchmarks"):
        sources += [
            p
            for p in (ROOT / directory).rglob("*")
            if p.is_file()
            and (p.suffix in (".rs", ".toml", ".py") or p.name == "Client.Dockerfile")
        ]
    sources += [
        ROOT / "examples/interop/python" / name
        for name in ("batched_load.c", "cache_load.py")
    ]
    sources += [
        ROOT / "examples/interop" / name
        for name in (
            "support/lock.py",
            "support/recursive_peers.py",
            "support/docker.py",
            "docker/Donna.Dockerfile",
            "docker/Bind.Dockerfile",
            "docker/Hickory.Dockerfile",
            "docker/KnotResolver.Dockerfile",
            "docker/Unbound.Dockerfile",
            "docker/CacheClient.Dockerfile",
        )
    ]
    record = {
        "date": datetime.datetime.now(datetime.UTC).isoformat(),
        "images": images,
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(sources)
        },
        "arguments": vars(args) | {"output": str(args.output)},
        "docker_host": run(
            "info",
            "--format",
            "{{.NCPU}} CPUs; {{.MemTotal}} bytes RAM; {{.Architecture}}; {{.KernelVersion}}",
        ),
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "resources": (
            f"Each container: {args.cpus} CPU quota, {args.memory} memory limit. "
            f"Each server: {args.workers} workers; Knot DNS: {args.workers} UDP + "
            f"{args.workers} TCP + 1 background worker. Shared Docker VM; no affinity."
        ),
        "container_limits": {},
        "roles": {"authority": AUTHORITY_ROLES, "recursive": RECURSIVE_ROLES},
        "configurations": {},
        "authority": [],
        "recursive": [],
        "cold": [],
        "complete": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(record, indent=2) + "\n")

    names = [CLIENT] + [PREFIX + role for role in ("root", "tld", "leaf", *images)]
    with laboratory_lock():
        try:
            run("network", "create", "--subnet", SUBNET + "0/24", NETWORK)
            run(
                "run",
                "-d",
                "--name",
                CLIENT,
                "--network",
                NETWORK,
                *limits,
                "--entrypoint",
                "sleep",
                images["client"],
                "infinity",
            )
            record["container_limits"]["client"] = container_limits(CLIENT)
            record["donna_binary_sha256"] = run(
                "exec", CLIENT, "sha256sum", "/usr/local/bin/donna"
            ).split()[0]
            record["versions"] = {
                "bind": run("run", "--rm", images["bind"], "named", "-v"),
                "knot": run("run", "--rm", images["knot"], "knotd", "-V"),
                "hickory": run(
                    "run", "--rm", images["hickory"], "hickory-dns", "--version"
                ),
                "kresd": run(
                    "run", "--rm", "--entrypoint", "kresd", images["kresd"], "-V"
                ),
                "unbound": run("run", "--rm", images["unbound"], "unbound", "-V"),
                "unbound_package": run(
                    "run", "--rm", images["unbound"], "dpkg-query", "-W", "unbound"
                ),
                "rust": run("run", "--rm", "rust:bookworm", "rustc", "--version"),
            }
            zone = (
                (ROOT / "examples/interop/fixtures/basic/zone.db")
                .read_text()
                .replace("172.29.53.20", SUBNET + "20")
            )

            def start(role, recursive=False):
                address = (
                    SUBNET
                    + {
                        "donna": "10",
                        "bind": "11",
                        "knot": "12",
                        "hickory": "13",
                        "kresd": "14",
                        "unbound": "15",
                    }[role]
                )
                files = {"zone.db": zone}
                command, extra = [], []
                if role == "donna":
                    text = (
                        'role = "'
                        + ("recursive" if recursive else "authoritative")
                        + '"\n'
                        '[[listen]]\nprotocol = "udp"\naddress = "' + address + ':53"\n'
                        '[[listen]]\nprotocol = "tcp"\naddress = "' + address + ':53"\n'
                        '[access]\nrecursion = ["' + SUBNET + '0/24"]\n'
                        '[resolver]\nvalidate = false\nroot_servers = ["'
                        + SUBNET
                        + '22:53"]\n'
                    )
                    if not recursive:
                        text += (
                            '[[zones]]\norigin = "example.test."\nfile = "zone.db"\n'
                        )
                    files["donna.toml"] = text
                    command = ["donna", "serve", "-c", "/bench/donna.toml"]
                elif role == "bind":
                    text = (
                        'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; '
                        "dnssec-validation no; querylog no; minimal-responses yes; "
                        + (
                            "recursion yes; allow-recursion { any; }; empty-zones-enable no; "
                            if recursive
                            else "recursion no; "
                        )
                        + "}; controls {};\n"
                    )
                    text += (
                        'zone "." { type hint; file "/bench/root.hints"; };\n'
                        if recursive
                        else 'zone "example.test" { type primary; file "/bench/zone.db"; };\n'
                    )
                    files["named.conf"] = text
                    command = [
                        "named",
                        "-g",
                        "-n",
                        str(args.workers),
                        "-c",
                        "/bench/named.conf",
                        "-u",
                        "root",
                    ]
                elif role == "knot":
                    files["knot.conf"] = (
                        "server:\n    rundir: /tmp\n    listen: 0.0.0.0@53\n"
                        f"    udp-workers: {args.workers}\n    tcp-workers: {args.workers}\n    background-workers: 1\n"
                        "log:\n  - target: stderr\n    any: error\ndatabase:\n    storage: /tmp/knot-db\n"
                        "zone:\n  - domain: example.test.\n    file: /bench/zone.db\n    dnssec-signing: off\n"
                    )
                    command = ["knotd", "-c", "/bench/knot.conf"]
                elif role == "unbound":
                    if not recursive:
                        raise ValueError("Unbound is a recursive-only peer")
                    files["unbound.conf"] = (
                        "server:\n"
                        "    interface: 0.0.0.0\n"
                        "    do-ip6: no\n"
                        f"    num-threads: {args.workers}\n"
                        '    chroot: ""\n'
                        '    username: ""\n'
                        '    pidfile: ""\n'
                        "    use-syslog: no\n"
                        "    verbosity: 0\n"
                        "    log-queries: no\n"
                        "    log-replies: no\n"
                        "    access-control: " + SUBNET + "0/24 allow\n"
                        '    root-hints: "/bench/root.hints"\n'
                        '    module-config: "iterator"\n'
                        # Unbound serves RFC 6761 test. locally by default.
                        '    local-zone: "test." nodefault\n'
                        "    msg-cache-size: 4m\n"
                        "    rrset-cache-size: 4m\n"
                        f"    msg-cache-slabs: {1 << (args.workers - 1).bit_length()}\n"
                        f"    rrset-cache-slabs: {1 << (args.workers - 1).bit_length()}\n"
                    )
                    command = ["unbound", "-d", "-c", "/bench/unbound.conf"]
                elif recursive:
                    filename, text = configuration(
                        "knot-resolver" if role == "kresd" else role,
                        signed=False,
                        workers=args.workers,
                    )
                    text = text.replace("/work/", "/bench/").replace(
                        "172.29.53.0/24", SUBNET + "0/24"
                    )
                    files[filename] = text
                    if role == "kresd":
                        extra = [
                            "--tmpfs",
                            "/var/cache/knot-resolver:rw,nosuid,nodev,size=80m",
                        ]
                    else:
                        command = [
                            "hickory-dns",
                            "--config",
                            "/bench/hickory.toml",
                            "--workers",
                            str(args.workers),
                            "--port",
                            "53",
                        ]
                else:
                    files["hickory.toml"] = (
                        'listen_addrs_ipv4 = ["0.0.0.0"]\nlisten_addrs_ipv6 = []\n'
                        'directory = "/bench"\ndrop_privileges = false\n[[zones]]\n'
                        'zone = "example.test."\nzone_type = "Primary"\nfile = "zone.db"\n'
                    )
                    command = [
                        "hickory-dns",
                        "--config",
                        "/bench/hickory.toml",
                        "--workers",
                        str(args.workers),
                        "--port",
                        "53",
                    ]
                files["root.hints"] = (
                    ". 3600 IN NS root.\nroot. 3600 IN A " + SUBNET + "22\n"
                )
                record["configurations"][
                    ("recursive/" if recursive else "authority/") + role
                ] = files
                name = PREFIX + role
                run(
                    "create",
                    "--name",
                    name,
                    "--network",
                    NETWORK,
                    "--ip",
                    address,
                    *limits,
                    "-e",
                    f"TOKIO_WORKER_THREADS={args.workers}",
                    "-e",
                    "RUST_LOG=error",
                    *extra,
                    images[role],
                    *command,
                )
                record["container_limits"][
                    ("recursive/" if recursive else "authority/") + role
                ] = container_limits(name)
                with tempfile.TemporaryDirectory(prefix=PREFIX) as tmp:
                    folder = Path(tmp) / "bench"
                    folder.mkdir()
                    for filename, text in files.items():
                        (folder / filename).write_text(text)
                    run("cp", str(folder), name + ":/bench")
                    if role == "kresd":
                        run(
                            "cp",
                            str(folder / "config.yaml"),
                            name + ":/etc/knot-resolver/config.yaml",
                        )
                run("start", name)
                if role == "donna":
                    digest = run(
                        "exec", name, "sha256sum", "/usr/local/bin/donna"
                    ).split()[0]
                    if digest != record["donna_binary_sha256"]:
                        raise RuntimeError("client and server Donna binaries differ")
                if role == "kresd":
                    for attempt in range(100):
                        try:
                            run("exec", name, "kresctl", "metrics")
                            break
                        except subprocess.CalledProcessError:
                            time.sleep(0.1)
                    else:
                        raise RuntimeError("Knot Resolver worker readiness failed")
                wait(address)
                return address

            if "cli" in args.phases or "authority" in args.phases:
                roles = AUTHORITY_ROLES
                addresses = {role: start(role) for role in roles}
                if "cli" in args.phases:
                    record["cli"] = worker("cli", addresses["bind"])
                    save()
                if "authority" in args.phases:
                    for case in ("positive", "negative", "wildcard"):
                        for repeat in range(args.repeats):
                            offset = repeat % len(roles)
                            for role in roles[offset:] + roles[:offset]:
                                row = worker(
                                    "load",
                                    addresses[role],
                                    "--case",
                                    case,
                                    "--seconds",
                                    str(args.seconds),
                                    "--repeat",
                                    str(repeat),
                                )
                                row["server"] = role
                                record["authority"].append(row)
                                save()
                                print(
                                    "authority",
                                    case,
                                    role,
                                    round(row["qps"]),
                                    flush=True,
                                )
                for role in roles:
                    remove(PREFIX + role)

            if "recursive" in args.phases:
                for role, apex, address, db in (
                    ("root", ".", "22", "root.db"),
                    ("tld", "test", "21", "tld.db"),
                    ("leaf", "example.test", "20", None),
                ):
                    data = (
                        zone
                        if db is None
                        else (ROOT / "examples/interop/fixtures/hierarchy" / db)
                        .read_text()
                        .replace("172.29.53.", SUBNET)
                    )
                    config = (
                        'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; recursion no; dnssec-validation no; }; controls {};\n'
                        'zone "'
                        + apex
                        + '" { type primary; file "/bench/zone.db"; };\n'
                    )
                    # docker cp creates /bench when its source is a named directory.
                    with tempfile.TemporaryDirectory(prefix=PREFIX) as tmp:
                        folder = Path(tmp) / "bench"
                        folder.mkdir()
                        (folder / "zone.db").write_text(data)
                        (folder / "named.conf").write_text(config)
                        name = PREFIX + role
                        run(
                            "create",
                            "--name",
                            name,
                            "--network",
                            NETWORK,
                            "--ip",
                            SUBNET + address,
                            *limits,
                            images["bind"],
                            "named",
                            "-g",
                            "-n",
                            str(args.workers),
                            "-c",
                            "/bench/named.conf",
                            "-u",
                            "root",
                        )
                        record["container_limits"]["hierarchy/" + role] = container_limits(name)
                        run("cp", str(folder), name + ":/bench")
                        run("start", name)
                    record["configurations"]["hierarchy/" + role] = {
                        "zone": data,
                        "config": config,
                    }
                    wait(SUBNET + address)
                roles = RECURSIVE_ROLES
                for repeat in range(args.cold_repeats):
                    offset = repeat % len(roles)
                    for role in roles[offset:] + roles[:offset]:
                        address = start(role, True)
                        row = worker("cold", address, "--recursive")
                        record["cold"].append(row | {"server": role, "repeat": repeat})
                        save()
                        print("cold", role, round(row["elapsed_ms"], 3), flush=True)
                        remove(PREFIX + role)
                addresses = {role: start(role, True) for role in roles}
                for case in ("positive", "negative", "cname"):
                    for repeat in range(args.repeats):
                        offset = repeat % len(roles)
                        for role in roles[offset:] + roles[:offset]:
                            row = worker(
                                "load",
                                addresses[role],
                                "--recursive",
                                "--case",
                                case,
                                "--seconds",
                                str(args.seconds),
                                "--repeat",
                                str(repeat),
                            )
                            row["server"] = role
                            record["recursive"].append(row)
                            save()
                            print(
                                "recursive", case, role, round(row["qps"]), flush=True
                            )
            record["complete"] = True
            save()
        except BaseException:
            for name in names:
                result = subprocess.run(
                    ["docker", "logs", "--tail", "10", name],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    print(name, result.stdout, result.stderr, file=sys.stderr)
            save()
            raise
        finally:
            for name in names:
                remove(name)
            subprocess.run(
                ["docker", "network", "rm", NETWORK],
                stdout=subprocess.DEVNULL,
                check=False,
            )


if __name__ == "__main__":
    main()

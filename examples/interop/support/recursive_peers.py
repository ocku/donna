"""Pinned recursive peers for the isolated signed root/TLD/leaf laboratory.

These peers perform iteration themselves; neither forwards to Donna or BIND.
Configuration files live in the caller's retained temporary directory.
"""

from pathlib import Path
import time

from support.docker import docker


KNOT_UPSTREAM = (
    "cznic/knot-resolver@sha256:"
    "9aa19d24179b173768a48713feeb2be782f9c29395f0d6a1470a9257e81287fc"
)
KNOT_IMAGE = "donna-interop-knot-resolver:6.5.1"
HICKORY_IMAGE = (
    "sha256:b40d16e1b92fac9a6819497293fe17c074e097e42e6eef246e3a8c90b0afdce7"
)


def configuration(role, signed=True, workers=1):
    """Use /work/root.hints and (when signed) /work/anchors.zone."""
    if role == "knot-resolver":
        dnssec = (
            "  enable: true\n  trust-anchors-files:\n"
            "    - file: /work/anchors.zone\n      read-only: true\n"
            if signed
            else "  enable: false\n"
        )
        return "config.yaml", (
            f"workers: {workers}\nlogging:\n  level: err\n"
            "network:\n  do-ipv6: false\n  listen:\n"
            "    - interface: 0.0.0.0@53\n"
            "cache:\n  size-max: 64M\n  ttl-min: 0s\n"
            "dnssec:\n"
            + dnssec
            + "lua:\n  script: |\n    modules.load('hints > iterate')\n"
            "    hints.root_file('/work/root.hints')\n"
            "    policy.add(policy.suffix(policy.PASS, policy.todnames({'test.'})))\n"
        )
    if role == "hickory":
        dnssec = (
            "\n[zones.stores.dnssec_policy.ValidateWithStaticKey]\n"
            'path = "/work/anchors.zone"\n'
            "validation_cache_size = 65536\n"
            if signed
            else ""
        )
        base = (
            'listen_addrs_ipv4 = ["0.0.0.0"]\n'
            'listen_addrs_ipv6 = []\ndrop_privileges = false\n\n[[zones]]\nzone = "."\n'
            'zone_type = "External"\n\n[zones.stores]\n'
            'type = "recursor"\nroots = "/work/root.hints"\n'
            "ns_cache_size = 1024\nresponse_cache_size = 65536\n"
            'allow_server = ["172.29.53.0/24"]\n'
        )
        # Hickory exposes entry counts, not a byte-limited cache. Its default
        # TTL policy is retained; do not claim an equal 64 MiB memory budget.
        return "hickory.toml", base + (dnssec if signed else "")
    raise ValueError("unknown recursive peer: " + role)


def start_peer(
    role, name, network, volume, address, directory, signed=True, image=None, workers=1
):
    """Start a peer; caller captures logs and removes it with docker rm -fv."""
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    filename, text = configuration(role, signed, workers)
    path = directory / filename
    path.write_text(text)
    args = [
        "create",
        "--name",
        name,
        "--network",
        network,
        "--ip",
        address,
        "--cpus",
        "1",
        "--memory",
        "256m",
        "-v",
        volume + ":/work:ro",
    ]
    if role == "knot-resolver":
        args += [
            "--tmpfs",
            "/var/cache/knot-resolver:rw,nosuid,nodev,size=80m",
            image or KNOT_IMAGE,
        ]
        target = "/etc/knot-resolver/config.yaml"
    elif role == "hickory":
        args += [
            "-e",
            "RUST_LOG=error",
            image or HICKORY_IMAGE,
            "hickory-dns",
            "--config",
            "/suite/recursive.toml",
            "--workers",
            str(workers),
            "--port",
            "53",
        ]
        target = "/suite/recursive.toml"
    else:
        raise ValueError("unknown recursive peer: " + role)
    container = docker(*args, capture=True)
    try:
        # Works with a remote Docker daemon; host bind mounts need not exist
        # on the daemon machine. Configuration is retained by the caller.
        docker("cp", str(path), name + ":" + target, capture=True)
        docker("start", name, capture=True)
        if role == "knot-resolver":
            # The manager temporarily binds sockets while applying its first
            # worker configuration. A TCP handshake alone is not readiness.
            deadline = time.monotonic() + 20
            while (
                docker(
                    "exec",
                    name,
                    "sh",
                    "-c",
                    "kresctl metrics >/tmp/ready-metrics.json 2>/dev/null && echo READY",
                    check=False,
                    capture=True,
                )
                != "READY"
            ):
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Knot Resolver manager/workers did not become ready"
                    )
                time.sleep(0.1)
        return container
    except BaseException:
        docker("rm", "-fv", name, check=False, capture=True)
        raise

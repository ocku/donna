"""Fixture deployment and provenance for authoritative comparison labs."""

import json
import time

from support.provenance import harness_hashes


def metadata(args, roles, workers, suite, harness, docker):
    return {
        "images": {
            role: json.loads(docker("image", "inspect", image, capture=True))[0]["Id"]
            for role, (image, _) in roles.items()
        },
        "client": args.load_client,
        "repeats": args.repeats,
        "seconds": args.seconds,
        "client_image_id": json.loads(
            docker(
                "image",
                "inspect",
                getattr(args, "client_image", "donna-interop-cache-client"),
                capture=True,
            )
        )[0]["Id"],
        "verify_wire": getattr(args, "verify_wire", False),
        "harness_sha256": harness_hashes(suite, harness),
        "suite": "upstream-semantics" if args.upstream_semantics else "throughput",
        "cases": args.cases,
        "modes": args.modes,
        "workers": workers,
        "outstanding": 32,
        "worker_configuration": {
            role: (
                f"{workers} UDP + {workers} TCP + 1 background"
                if role == "knot"
                else f"{workers} Tokio workers"
                if role in ("current", "verified", "hickory")
                else f"{workers} server workers"
            )
            for role in roles
        },
        "resource_limits": "No container CPU quota or CPU affinity; shared Docker host; only one timed client at a time",
        "logging": "Rust RUST_LOG=error; Knot error only; no per-query server-log growth permitted",
        "docker_host": docker(
            "info",
            "--format",
            "{{.NCPU}} CPUs; {{.MemTotal}} bytes RAM; {{.Architecture}}; {{.KernelVersion}}",
            capture=True,
        ),
    }


def prepare(directory, args, *, suite, prefix, network, volume, workers, put, docker):
    text = (suite / "fixtures/basic/zone.db").read_text() + (
        '\na.wild IN TXT "lower boundary"\nz.wild IN TXT "upper boundary"\n'
        'leaf.deep.empty IN TXT "creates two empty nonterminals"\nalias-empty IN CNAME empty.example.test.\n'
    )
    if args.upstream_semantics:
        text = (suite / "fixtures/authority/upstream.zone").read_text()
    put(directory, "zone.db", text)
    put(directory, "unsigned.db", text)
    pre_signed = getattr(args, "pre_signed_fixtures", None)
    if pre_signed:
        for mode, signed_text in pre_signed.items():
            put(directory, mode + ".db", signed_text)
    else:
        docker(
            "cp",
            str(suite / "docker/sign-zone.sh"),
            prefix + "signer:/sign-zone.sh",
        )
        docker("exec", prefix + "signer", "sh", "/sign-zone.sh", capture=True)
    put(
        directory,
        "named.conf",
        'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; recursion no; '
        "dnssec-validation no; minimal-responses yes; querylog no; max-udp-size 1232; check-names primary ignore; };\n"
        'controls {};\nzone "example.test" { type primary; file "/work/active.db"; };\n',
    )
    put(
        directory,
        "hickory.toml",
        'listen_addrs_ipv4 = ["0.0.0.0"]\nlisten_addrs_ipv6 = []\n'
        'listen_port = 53\ndirectory = "/work"\ndrop_privileges = false\n'
        '[[zones]]\nzone = "example.test."\nzone_type = "Primary"\nfile = "active.db"\n'
        'axfr_policy = "AllowAll"\n',
    )
    put(
        directory,
        "knot.conf",
        f"server:\n    rundir: /tmp\n    listen: 0.0.0.0@53\n    udp-workers: {workers}\n    tcp-workers: {workers}\n"
        "    background-workers: 1\n    udp-max-payload: 1232\nlog:\n  - target: stderr\n    any: error\n"
        "database:\n    storage: /tmp/knot-db\ntemplate:\n  - id: default\n    storage: /tmp\n    zonefile-sync: -1\n"
        "zone:\n  - domain: example.test.\n    file: /work/active.db\n    dnssec-signing: off\n",
    )
    put(
        directory,
        "nsd.conf",
        f"server:\n    ip-address: 0.0.0.0@53\n    ip4-only: yes\n    server-count: {workers}\n"
        '    reuseport: yes\n    username: root\n    chroot: ""\n    pidfile: /tmp/nsd.pid\n'
        '    database: ""\n    zonesdir: /work\n    logfile: /dev/stderr\n    verbosity: 0\n'
        "    minimal-responses: yes\n    ipv4-edns-size: 1232\nremote-control:\n    control-enable: no\n"
        "zone:\n    name: example.test.\n    zonefile: /work/active.db\n",
    )
    for name in ("probe", "client"):
        image = (
            "donna-interop-peers"
            if name == "probe"
            else getattr(args, "client_image", "donna-interop-cache-client")
        )
        docker(
            "run",
            "-d",
            "--name",
            prefix + name,
            "--network",
            network,
            "-v",
            volume + ":/work:ro",
            "--entrypoint",
            "sleep",
            image,
            "infinity",
            capture=True,
        )
        for module in (
            "similar_load.py",
            "signed_probe.py",
            "authority_replay.py",
        ):
            docker(
                "cp",
                str(suite / "python" / module),
                prefix + name + ":/suite/" + module,
            )
        docker(
            "cp",
            str(suite / "support/server_cpu.py"),
            prefix + name + ":/suite/server_cpu.py",
        )


def start(mode, *, roles, prefix, network, volume, certs, workers, docker):
    docker("exec", prefix + "signer", "cp", f"/work/{mode}.db", "/work/active.db")
    for role, (image, address) in roles.items():
        args = [
            "run",
            "-d",
            "--name",
            prefix + role,
            "--network",
            network,
            "--ip",
            address,
            "-v",
            volume + ":/work:ro",
        ]
        if role in ("verified", "current"):
            args += [
                "-v",
                certs + ":/certs:ro",
                "-e",
                "LISTEN_HOST=" + address,
                "-e",
                "ZONE_FILE=/work/active.db",
                "-e",
                "RUST_LOG=error",
                "-e",
                f"TOKIO_WORKER_THREADS={workers}",
                image,
            ]
        elif role == "bind":
            args += [
                image,
                "named",
                "-g",
                "-n",
                str(workers),
                "-c",
                "/work/named.conf",
                "-u",
                "root",
            ]
        elif role == "knot":
            args += [image, "knotd", "-c", "/work/knot.conf"]
        elif role == "hickory":
            args += [
                "-e",
                "RUST_LOG=error",
                image,
                "hickory-dns",
                "--config",
                "/work/hickory.toml",
                "--workers",
                str(workers),
                "--port",
                "53",
            ]
        else:
            args += [image, "nsd", "-d", "-c", "/work/nsd.conf"]
        docker(*args, capture=True)
    # Connection readiness only; independent DNS gates below warm and verify.
    deadline = time.monotonic() + 15
    while True:
        command = [
            "python",
            "-c",
            "import socket; "
            + "; ".join(
                f"socket.create_connection(('{address}',{5300 if role in ('verified', 'current') else 53}),.3).close()"
                for role, (_, address) in roles.items()
            )
            + "; print('ready')",
        ]
        if (
            docker(
                "exec", prefix + "probe", *command, check=False, capture=True
            ).strip()
            == "ready"
        ):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("authorities did not become ready")
        time.sleep(0.05)

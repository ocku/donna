#!/usr/bin/env python3
"""Compare explicitly anchored, cached DNSSEC-validating recursive service."""

from support.lock import exclusive_laboratory
from support.daemon import create_recursive

import argparse
import json
import hashlib
from support.paths import SUITE
from pathlib import Path
import tempfile
import time

from support.topology import NETWORK, PREFIX, docker
from labs.dnssec.signed import SIGNER, VOLUME, check_mode, cleanup, prepare

RESOLVERS = (PREFIX + "validating-donna", PREFIX + "validating-bind")
CLIENT = PREFIX + "validating-client"
WORKLOADS = ("positive", "negative", "nodata", "cname", "wildcard", "cname_negative")


def stop_resolvers():
    docker("rm", "-f", *RESOLVERS, check=False, capture=True)


def start_resolvers(image):
    stop_resolvers()
    docker(
        "run",
        "-d",
        "--name",
        RESOLVERS[1],
        "--network",
        NETWORK,
        "--ip",
        "172.29.53.60",
        "-v",
        VOLUME + ":/work:ro",
        PREFIX + "bind",
        "named",
        "-g",
        "-n",
        "2",
        "-c",
        "/work/validating.conf",
        "-u",
        "root",
        capture=True,
    )
    create_recursive(
        RESOLVERS[0],
        image,
        NETWORK,
        "172.29.53.61",
        "172.29.53.24:53",
        "172.29.53.0/24",
        anchors="/work/anchors.zone",
        options=("-v", VOLUME + ":/work:ro"),
    )
    # Only socket readiness is probed; measured DNS owners remain untouched.
    for _ in range(50):
        ready = docker(
            "exec",
            PREFIX + "probe",
            "python",
            "-c",
            "import socket; "
            "socket.create_connection(('172.29.53.60',53),timeout=.2).close(); "
            "socket.create_connection(('172.29.53.61',5301),timeout=.2).close()",
            check=False,
            capture=True,
        )
        if "Traceback" not in ready and "Error" not in ready:
            return
        time.sleep(0.1)
    raise RuntimeError("validating resolvers failed to become ready")


def configure(directory):
    docker("cp", SIGNER + ":/work/nsec.db", str(directory / "public.zone"))
    docker(
        "cp",
        str(directory / "public.zone"),
        PREFIX + "probe:/suite/validating-public.zone",
    )
    keys = json.loads(
        docker(
            "exec",
            PREFIX + "probe",
            "python",
            "-c",
            "import dns.zone,dns.rdatatype,json; "
            "z=dns.zone.from_file('/suite/validating-public.zone',origin='example.test.',relativize=False); "
            "print(json.dumps([k.to_text() for k in z.get_rdataset('example.test.',dns.rdatatype.DNSKEY) if k.flags==257]))",
            capture=True,
        )
    )
    if not keys:
        raise RuntimeError("missing independent BIND KSK")
    (directory / "anchors.zone").write_text(
        "".join("example.test. 300 IN DNSKEY " + key + "\n" for key in keys)
    )
    anchors = ""
    for key in keys:
        flags, protocol, algorithm, *parts = key.split()
        anchors += f'"example.test." static-key {flags} {protocol} {algorithm} "{"".join(parts)}";\n'
    (directory / "validating.conf").write_text(
        'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; '
        "recursion yes; allow-recursion { 172.29.53.0/24; }; dnssec-validation yes; "
        "empty-zones-enable no; max-cache-size 64m; minimal-responses yes; };\n"
        "trust-anchors { " + anchors + " };\n"
        'zone "example.test." { type forward; forward only; forwarders { 172.29.53.24 port 53; }; };\n'
    )
    for filename in ("anchors.zone", "validating.conf"):
        docker("cp", str(directory / filename), SIGNER + ":/work/" + filename)
    docker("exec", SIGNER, "named-checkconf", "/work/validating.conf")
    print(
        json.dumps(
            {
                "fixture": "example.test public KSK anchors",
                "dnskeys": keys,
                "anchor_sha256": hashlib.sha256(
                    (directory / "anchors.zone").read_bytes()
                ).hexdigest(),
            }
        ),
        flush=True,
    )


def client(mode, repeats, seconds, bogus=False, workloads=None, load_client="dnsperf"):
    command = [
        "exec",
        CLIENT,
        "python",
        "/suite/validating_load.py",
        "--mode",
        mode,
        "--repeats",
        str(repeats),
        "--seconds",
        str(seconds),
        "--load-client",
        load_client,
    ]
    if bogus:
        command += ["--verify-bogus"]
    for workload in workloads or []:
        command += ["--workload", workload]
    return docker(*command, capture=True)


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", default=PREFIX + "donna")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=2)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument(
        "--mode",
        choices=("nsec", "nsec3", "nsec3-secure", "both", "all"),
        default="all",
    )
    parser.add_argument(
        "--workload",
        action="append",
        choices=WORKLOADS,
        help="limit an exploratory timing run; defaults to all workloads",
    )
    parser.add_argument(
        "--isolate-workloads",
        action="store_true",
        help="restart both resolvers before each workload; separates warm comparisons from cross-workload expiry",
    )
    args = parser.parse_args()
    if args.repeats < 1 or args.seconds < 1:
        parser.error("repeats and seconds must be positive")
    suite = SUITE
    cleanup()
    stop_resolvers()
    docker("rm", "-f", CLIENT, check=False, capture=True)
    try:
        docker(
            "run",
            "-d",
            "--name",
            CLIENT,
            "--network",
            NETWORK,
            "--entrypoint",
            "sleep",
            PREFIX + "cache-client",
            "infinity",
            capture=True,
        )
        docker(
            "cp",
            str(suite / "python/validating_load.py"),
            CLIENT + ":/suite/validating_load.py",
        )
        docker(
            "cp", str(suite / "python/cache_load.py"), CLIENT + ":/suite/cache_load.py"
        )
        with tempfile.TemporaryDirectory(prefix="donna-validating-") as temporary:
            directory = Path(temporary)
            prepare(directory, suite, authority_address="172.29.53.24")
            docker(
                "exec",
                "-w",
                "/work",
                SIGNER,
                "dnssec-signzone",
                "-q",
                "-S",
                "-n",
                "1",
                "-s",
                "now-3600",
                "-e",
                "now+86400",
                "-N",
                "keep",
                "-3",
                "A1B2",
                "-o",
                "example.test.",
                "-f",
                "nsec3-secure.db",
                "zone.db",
            )
            configure(directory)
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
                        },
                        "scope": "explicitly anchored cached validation, not root-to-leaf chain throughput",
                    }
                ),
                flush=True,
            )
            modes = {
                "both": ("nsec", "nsec3"),
                "all": ("nsec", "nsec3", "nsec3-secure"),
            }.get(args.mode, (args.mode,))
            for mode in modes:
                print(
                    json.dumps(
                        {
                            "mode": mode,
                            "signed_zone_sha256": docker(
                                "exec",
                                SIGNER,
                                "sha256sum",
                                f"/work/{mode}.db",
                                capture=True,
                            ).split()[0],
                        }
                    ),
                    flush=True,
                )
                # BIND loads deliberately tampered A RDATA with its original
                # signatures. Both recursive validators must reject it.
                docker(
                    "exec",
                    SIGNER,
                    "sh",
                    "-c",
                    f"sed 's/192.0.2.80/192.0.2.81/g' /work/{mode}.db > /work/active.db",
                )
                docker(
                    "run",
                    "-d",
                    "--name",
                    PREFIX + "signed-bind",
                    "--network",
                    NETWORK,
                    "--ip",
                    "172.29.53.24",
                    "-v",
                    VOLUME + ":/work:ro",
                    PREFIX + "bind",
                    "named",
                    "-g",
                    "-n",
                    "2",
                    "-c",
                    "/work/named.conf",
                    "-u",
                    "root",
                    capture=True,
                )
                start_resolvers(args.donna_image)
                print(client(mode, args.repeats, args.seconds, bogus=True), flush=True)
                stop_resolvers()
                if check_mode(
                    "nsec" if mode == "nsec" else "nsec3",
                    args.donna_image,
                    zone_file=mode + ".db",
                ):
                    raise RuntimeError(
                        "independent signed authority verification failed"
                    )
                docker("rm", "-f", PREFIX + "signed-donna", capture=True)
                groups = (
                    [[workload] for workload in (args.workload or WORKLOADS)]
                    if args.isolate_workloads
                    else [args.workload]
                )
                for workloads in groups:
                    print(
                        json.dumps(
                            {
                                "measurement_policy": "fresh resolvers per workload"
                                if args.isolate_workloads
                                else "shared resolvers across workloads",
                                "mode": mode,
                                "workloads": workloads or list(WORKLOADS),
                                "timed_seconds_per_workload": 2
                                * args.repeats
                                * args.seconds,
                                "total_timed_seconds": 2
                                * args.repeats
                                * args.seconds
                                * len(workloads or WORKLOADS),
                            }
                        ),
                        flush=True,
                    )
                    start_resolvers(args.donna_image)
                    docker(
                        "cp",
                        str(suite / "python/recursive_negative_probe.py"),
                        PREFIX + "probe:/suite/recursive_negative_probe.py",
                    )
                    docker(
                        "exec",
                        PREFIX + "probe",
                        "python",
                        "recursive_negative_probe.py",
                        "--mode",
                        mode,
                        "--phase",
                        "before",
                    )
                    output = client(
                        mode,
                        args.repeats,
                        args.seconds,
                        workloads=workloads,
                        load_client=args.load_client,
                    )
                    for line in output.splitlines():
                        if line.startswith('{"server"'):
                            row = json.loads(line)
                            row.update(
                                signed_mode=mode,
                                donna_image=args.donna_image,
                                isolated_workloads=args.isolate_workloads,
                                authenticated_data_expected=not (
                                    mode == "nsec3"
                                    and row["workload"] in ("negative", "wildcard")
                                ),
                                scope="cached validating recursive UDP; example.test DNSKEY anchor; direct terminal authority, no delegation-chain timing",
                            )
                            print(json.dumps(row), flush=True)
                        else:
                            print(line, flush=True)
                    docker(
                        "exec",
                        PREFIX + "probe",
                        "python",
                        "recursive_negative_probe.py",
                        "--mode",
                        mode,
                        "--phase",
                        "after",
                    )
                    stop_resolvers()
                docker("rm", "-f", PREFIX + "signed-bind", capture=True)
    except Exception:
        for container in (*RESOLVERS, PREFIX + "signed-bind"):
            docker("logs", "--tail", "30", container, check=False)
        raise
    finally:
        stop_resolvers()
        docker("rm", "-f", CLIENT, check=False, capture=True)
        cleanup()


if __name__ == "__main__":
    main()

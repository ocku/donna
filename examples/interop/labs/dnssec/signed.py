#!/usr/bin/env python3
"""Generate independent DNSSEC fixtures and compare local signed authorities."""

from support.paths import SUITE
from pathlib import Path
from support.lock import exclusive_laboratory

import argparse
import tempfile
import time

from support.topology import CERTS, NETWORK, PREFIX, docker

SERVICES = ("signed-donna", "signed-bind")
VOLUME = PREFIX + "signed-fixtures"
SIGNER = PREFIX + "signer"


def stop():
    docker("rm", "-f", *(PREFIX + name for name in SERVICES), check=False, capture=True)


def cleanup():
    stop()
    docker("rm", "-f", SIGNER, check=False, capture=True)
    docker("volume", "rm", VOLUME, check=False, capture=True)


def prepare(directory, suite, *, authority_address=None, extra_records=""):
    text = (suite / "fixtures/basic/zone.db").read_text()
    if authority_address is not None:
        # Recursive fixtures follow this glue; keep it on the same freshly
        # signed authority rather than the ordinary unsigned laboratory peer.
        text = text.replace("172.29.53.20", authority_address)
    # Separate canonical intervals expose missing expanded-name proofs.
    text += 'a.wild IN TXT "lower boundary"\nz.wild IN TXT "upper boundary"\n'
    text += 'leaf.deep.empty IN TXT "creates two empty nonterminals"\n'
    text += "alias-empty IN CNAME empty.example.test.\n"
    text += extra_records
    (directory / "zone.db").write_text(text)
    docker("volume", "create", VOLUME, capture=True)
    docker(
        "run",
        "-d",
        "--name",
        SIGNER,
        "--network",
        "none",
        "-v",
        VOLUME + ":/work",
        PREFIX + "bind",
        "sleep",
        "infinity",
        capture=True,
    )
    docker("cp", str(directory / "zone.db"), SIGNER + ":/work/zone.db")
    docker("cp", str(suite / "docker/sign-zone.sh"), SIGNER + ":/sign-zone.sh")
    docker("exec", SIGNER, "sh", "/sign-zone.sh")
    (directory / "named.conf").write_text(
        'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; '
        "recursion no; dnssec-validation no; };\n"
        'zone "example.test" { type primary; file "/work/active.db"; };\n'
    )
    docker("cp", str(directory / "named.conf"), SIGNER + ":/work/named.conf")
    docker(
        "cp",
        str(suite / "python/signed_probe.py"),
        PREFIX + "probe:/suite/signed_probe.py",
    )


def check_mode(mode, donna_image=None, *, zone_file=None):
    stop()
    docker(
        "exec", SIGNER, "cp", "/work/" + (zone_file or f"{mode}.db"), "/work/active.db"
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
    docker(
        "run",
        "-d",
        "--name",
        PREFIX + "signed-donna",
        "--network",
        NETWORK,
        "--ip",
        "172.29.53.14",
        "-v",
        VOLUME + ":/work:ro",
        "-v",
        CERTS + ":/certs:ro",
        "-e",
        "LISTEN_HOST=172.29.53.14",
        "-e",
        "ZONE_FILE=/work/active.db",
        "-e",
        "TOKIO_WORKER_THREADS=2",
        donna_image or PREFIX + "donna",
        capture=True,
    )
    time.sleep(1)
    result = docker(
        "exec", PREFIX + "probe", "python", "signed_probe.py", mode, check=False
    )
    # Exercise Donna's public cryptographic verifier against BIND's captures,
    # independently of the network replies produced by Donna's server.
    with tempfile.TemporaryDirectory(prefix="donna-proof-") as temporary:
        docker("cp", PREFIX + "probe:/suite/captures/.", temporary)
        docker("exec", PREFIX + "signed-donna", "mkdir", "-p", "/tmp/denial-captures")
        docker("cp", temporary + "/.", PREFIX + "signed-donna:/tmp/denial-captures/")
        validation = docker(
            "exec",
            PREFIX + "signed-donna",
            "validate_denial",
            "/tmp/denial-captures",
            mode,
            check=False,
        )
    if result or validation:
        docker("logs", "--tail", "10", PREFIX + "signed-donna", check=False)
    return result or validation


@exclusive_laboratory
def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-dir", type=Path)
    parser.add_argument(
        "--donna-image", help="explicit Donna runtime image used for signed checks"
    )
    parser.add_argument(
        "--zone-dir", type=Path, help="export the public BIND-signed zone fixtures"
    )
    args = parser.parse_args(argv)
    suite = SUITE
    cleanup()
    try:
        with tempfile.TemporaryDirectory(prefix="donna-signed-") as temporary:
            prepare(Path(temporary), suite)
            if args.zone_dir:
                args.zone_dir.mkdir(parents=True, exist_ok=True)
                for mode in ("nsec", "nsec3"):
                    docker(
                        "cp",
                        SIGNER + f":/work/{mode}.db",
                        str(args.zone_dir / f"bind-{mode}.zone"),
                    )
            errors = [
                mode for mode in ("nsec", "nsec3") if check_mode(mode, args.donna_image)
            ]
            if args.capture_dir:
                args.capture_dir.mkdir(parents=True, exist_ok=True)
                docker("cp", PREFIX + "probe:/suite/captures/.", str(args.capture_dir))
            if errors:
                raise SystemExit("Signed proof checks failed: " + ", ".join(errors))
    finally:
        cleanup()


if __name__ == "__main__":
    main()

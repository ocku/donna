#!/usr/bin/env python3
"""Build and run the isolated laboratory using only Docker's ordinary CLI."""

from support.lock import exclusive_laboratory

import argparse

from support.topology import CERTS, NETWORK, PREFIX, STATE, docker
from support.cli import query_fixture, resolve_fixture

SERVICES = (
    "donna",
    "recursive",
    "updates",
    "bind",
    "tld",
    "root",
    "peers",
    "probe",
    "hickory",
)


def cleanup():
    from labs.dnssec.signed import cleanup as cleanup_signed

    cleanup_signed()
    docker(
        "rm",
        "-f",
        *(PREFIX + service for service in SERVICES),
        check=False,
        capture=True,
    )
    docker("network", "rm", NETWORK, check=False, capture=True)
    docker("volume", "rm", CERTS, STATE, check=False, capture=True)


def start(
    service, image, address, command=(), environment=(), mounts=(), *, image_ref=None
):
    args = [
        "run",
        "-d",
        "--name",
        PREFIX + service,
        "--network",
        NETWORK,
        "--ip",
        address,
        "-v",
        CERTS + ":/certs:ro",
    ]
    for variable in environment:
        args += ["-e", variable]
    for mount in mounts:
        args += ["-v", mount]
    docker(*args, image_ref or PREFIX + image, *command, capture=True)


def probe(*command):
    docker("exec", PREFIX + "probe", *command)


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument(
        "--donna-image", help="use an explicit Donna image without rebuilding it"
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep running lab after checks, including on failure",
    )
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--fuzz", type=int, default=200)
    parser.add_argument(
        "--with-hickory",
        action="store_true",
        help="add the pinned Hickory authority and clients",
    )
    parser.add_argument("--hickory-image", default="donna-interop-hickory:0.26.3")
    args = parser.parse_args()
    cleanup()
    if args.cleanup:
        return
    try:
        if not args.skip_build:
            for image, filename in (
                ("donna", "Donna"),
                ("peers", "Peers"),
                ("bind", "Bind"),
                ("node", "Node"),
                ("go", "Go"),
            ):
                if image == "donna" and args.donna_image:
                    continue
                docker(
                    "build",
                    "-t",
                    PREFIX + image,
                    "-f",
                    f"examples/interop/docker/{filename}.Dockerfile",
                    ".",
                )
            if args.with_hickory:
                docker(
                    "build",
                    "-t",
                    args.hickory_image,
                    "-f",
                    "examples/interop/docker/Hickory.Dockerfile",
                    ".",
                )
        docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
        docker("volume", "create", CERTS, capture=True)
        docker("volume", "create", STATE, capture=True)
        docker(
            "run",
            "--rm",
            "-v",
            CERTS + ":/certs",
            PREFIX + "peers",
            "python",
            "certificates.py",
        )
        start(
            "bind",
            "bind",
            "172.29.53.20",
            (
                "named",
                "-g",
                "-n",
                "2",
                "-c",
                "/suite/fixtures/basic/named.conf",
                "-u",
                "root",
            ),
        )
        if args.with_hickory:
            start("hickory", "hickory", "172.29.53.50", image_ref=args.hickory_image)
        for service, ip in (("root", "172.29.53.22"), ("tld", "172.29.53.21")):
            start(
                service,
                "bind",
                ip,
                (
                    "named",
                    "-g",
                    "-n",
                    "2",
                    "-c",
                    f"/suite/fixtures/hierarchy/{service}.conf",
                    "-u",
                    "root",
                ),
            )
        start(
            "donna",
            "donna",
            "172.29.53.10",
            environment=("LISTEN_HOST=172.29.53.10",),
            image_ref=args.donna_image,
        )
        start(
            "recursive",
            "donna",
            "172.29.53.11",
            ("donna", "serve", "-c", "/suite/fixtures/basic/recursive.toml"),
            image_ref=args.donna_image,
        )
        start(
            "updates",
            "donna",
            "172.29.53.12",
            ("updates",),
            (
                "UPDATE_LISTEN=172.29.53.12:5301",
                "SNAPSHOT_FILE=/state/zone.wire",
                "NOTIFY_TARGET=172.29.53.40:5401",
            ),
            (STATE + ":/state",),
            image_ref=args.donna_image,
        )
        start("peers", "peers", "172.29.53.30")
        start("probe", "peers", "172.29.53.40", ("sleep", "infinity"))
        docker("cp", "examples/interop/python/.", PREFIX + "probe:/suite/")
        probe("python", "ready.py")
        probe("python", "probe.py", "--fuzz", str(args.fuzz))
        probe("python", "semantics.py")
        probe("python", "http_errors.py")
        probe("python", "edns_errors.py")
        probe("python", "stream_abuse.py")
        for language in ("node", "go"):
            docker(
                "run",
                "--rm",
                "--network",
                NETWORK,
                "-v",
                CERTS + ":/certs:ro",
                PREFIX + language,
            )
        provider_key = docker(
            "exec",
            PREFIX + "probe",
            "python",
            "-c",
            "from crypto_peer import PROVIDER_SECRET, SigningKey; "
            "print(SigningKey(PROVIDER_SECRET).verify_key.encode().hex())",
            capture=True,
        )
        for protocol, port in (
            ("udp", 53),
            ("tcp", 53),
            ("tls", 8530),
            ("doh-get", 8443),
            ("doh-post", 8443),
            ("doq", 8853),
            ("dnscrypt-udp", 5443),
            ("dnscrypt-tcp", 5443),
        ):
            peer = "172.29.53.20" if protocol in ("udp", "tcp") else "172.29.53.30"
            query_fixture(
                PREFIX + "donna", protocol, f"{peer}:{port}", provider_key=provider_key
            )
        # Exercise the shipped client against both Donna daemon roles.
        for address in ("172.29.53.10:5300", "172.29.53.11:5301"):
            for protocol in ("udp", "tcp"):
                query_fixture(PREFIX + "donna", protocol, address)
        resolve_fixture(PREFIX + "donna", "172.29.53.22:53")
        # Keep the library hook: it observes cache hits and upstream transmissions.
        docker("exec", PREFIX + "donna", "iterative_client")
        if args.with_hickory:
            from labs.transport.hickory_clients import check_clients

            check_clients(
                args.hickory_image,
                NETWORK,
                (
                    ("authority", "172.29.53.10:5300"),
                    ("recursive", "172.29.53.11:5301"),
                ),
            )
            for protocol in ("udp", "tcp"):
                query_fixture(PREFIX + "donna", protocol, "172.29.53.50:53")
        probe("python", "recursive_probe.py")
        for language, command in (
            ("node", ("node", "recursive.mjs")),
            ("go", ("recursive-client",)),
        ):
            docker("run", "--rm", "--network", NETWORK, PREFIX + language, *command)
        probe("python", "update_notify.py", "172.29.53.12")
        docker("restart", PREFIX + "updates", capture=True)
        probe("python", "ready.py")
        probe("python", "update_notify.py", "172.29.53.12", "--verify-restart")
        probe("python", "sig0_probe.py", "172.29.53.12")
        transfer = docker(
            "exec",
            PREFIX + "bind",
            "dig",
            "@172.29.53.10",
            "-p",
            "5300",
            "example.test.",
            "AXFR",
            "+tcp",
            capture=True,
        )
        assert "XFR size:" in transfer and "192.0.2.80" in transfer, transfer
        print("PASS independent BIND dig AXFR client against Donna", flush=True)
        from labs.dnssec.signed import main as signed_checks

        signed_checks(["--donna-image", args.donna_image] if args.donna_image else [])
        print("PASS complete bounded interoperability laboratory", flush=True)
    except Exception as error:
        for service in SERVICES:
            print(f"--- {service} logs ---", flush=True)
            docker("logs", "--tail", "30", PREFIX + service, check=False)
        raise SystemExit(str(error)) from error
    finally:
        if not args.keep:
            cleanup()


if __name__ == "__main__":
    main()

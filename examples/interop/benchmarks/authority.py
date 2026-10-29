#!/usr/bin/env python3
"""Compare independently signed authoritative UDP service against BIND."""

from support.lock import exclusive_laboratory

import argparse
import json
from support.paths import SUITE
from pathlib import Path
import tempfile

from support.topology import NETWORK, PREFIX, docker
from labs.dnssec.signed import check_mode, cleanup, prepare


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("nsec", "nsec3", "both"), default="both")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=2)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument(
        "--cold-population",
        type=int,
        default=0,
        help="finite distinct owners, queried once per trial",
    )
    parser.add_argument("--donna-image", default=PREFIX + "donna")
    args = parser.parse_args()
    if args.repeats < 1 or args.seconds < 1:
        parser.error("repeats and seconds must be positive")
    if not 0 <= args.cold_population <= 2048:
        parser.error("cold population must be 0..2048")
    suite = SUITE
    cleanup()
    try:
        with tempfile.TemporaryDirectory(prefix="donna-authority-load-") as temporary:
            extra = "".join(
                f"fresh-positive-{repeat}-{i} IN A 192.0.2.80\n"
                f'fresh-nodata-{repeat}-{i} IN TXT "exists without A"\n'
                for repeat in range(args.repeats)
                for i in range(args.cold_population)
            )
            prepare(Path(temporary), suite, extra_records=extra)
            if args.cold_population:
                docker(
                    "cp",
                    str(suite / "python/fresh_authority_verify.py"),
                    PREFIX + "probe:/suite/fresh_authority_verify.py",
                )
            for mode in ("nsec", "nsec3") if args.mode == "both" else (args.mode,):
                if check_mode(mode, args.donna_image):
                    raise RuntimeError(
                        "signed verification failed before timing " + mode
                    )
                output = docker(
                    "run",
                    "--rm",
                    "--network",
                    NETWORK,
                    "--entrypoint",
                    "python",
                    PREFIX + "cache-client",
                    "/suite/authority_load.py",
                    "--mode",
                    mode,
                    "--repeats",
                    str(args.repeats),
                    "--seconds",
                    str(args.seconds),
                    "--load-client",
                    args.load_client,
                    "--cold-population",
                    str(args.cold_population),
                    capture=True,
                )
                for line in output.splitlines():
                    if line.startswith("{"):
                        row = json.loads(line)
                        row.update(
                            signed_mode=mode,
                            donna_image=args.donna_image,
                            scope=(
                                "finite first-time signed authoritative owners; no measured-owner warmup"
                                if args.cold_population
                                else "signed authoritative UDP; no recursive validation"
                            ),
                        )
                        print(json.dumps(row), flush=True)
                if args.cold_population:
                    print(
                        docker(
                            "exec",
                            PREFIX + "probe",
                            "python",
                            "/suite/fresh_authority_verify.py",
                            "--mode",
                            mode,
                            "--population",
                            str(args.cold_population),
                            "--repeats",
                            str(args.repeats),
                            capture=True,
                        ),
                        flush=True,
                    )
    finally:
        cleanup()


if __name__ == "__main__":
    main()

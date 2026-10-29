"""Command-line policy for the authoritative comparison laboratory."""

import argparse


def arguments(roles, services):
    parser = argparse.ArgumentParser(
        description="Compare matched authoritative Docker peers without changing Donna source."
    )
    parser.add_argument(
        "--load-client", choices=("batched", "dnsperf"), default="batched"
    )
    parser.add_argument(
        "--control-image",
        default=roles["verified"][0],
        help="frozen Donna control image (never rebuilt by this runner)",
    )
    parser.add_argument(
        "--current-image",
        default=roles["current"][0],
        help="Donna candidate image (never rebuilt by this runner)",
    )
    parser.add_argument("--hickory-image", default=roles["hickory"][0])
    parser.add_argument(
        "--roles",
        nargs="+",
        choices=services,
        default=["verified", "current", "bind", "knot", "nsd"],
        help="select matched peers, e.g. current knot hickory",
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=2)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument(
        "--server-cpu",
        action="store_true",
        help="pause each trial to sample Linux server-process CPU ticks",
    )
    parser.add_argument(
        "--verify-wire",
        action="store_true",
        help="require exact immutable response bodies during native authoritative load",
    )
    parser.add_argument("--client-image", default="donna-interop-cache-client")
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=("unsigned", "nsec", "nsec3"),
        default=["unsigned", "nsec", "nsec3"],
    )
    parser.add_argument(
        "--cases",
        nargs="+",
        choices=("positive", "negative", "nodata", "wildcard", "wildcard-nodata"),
    )
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument(
        "--upstream-semantics",
        action="store_true",
        help="check the dedicated unsigned wildcard/empty-node fixture instead of timing",
    )
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    if args.repeats < 1 or args.seconds < 1 or not 1 <= args.workers <= 64:
        parser.error("positive repeat count/duration and 1..64 workers required")
    return args

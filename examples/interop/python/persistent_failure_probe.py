"""Measure repeated failure retry epochs without assuming a peer is an oracle."""

import json
import time
from urllib.request import Request, urlopen

from recursive_cache_checks import total
from recursive_cache_probe import AUTHORITY, SERVERS, ZONE, counts
from resolution_failure_probe import query


def main():
    states = []
    for label, host, port in SERVERS:
        name = f"servfail-persistent-{label}.{ZONE}"
        states.append((label, host, port, name))
    start = time.monotonic()
    rows = []
    # A quarter-second observation interval distinguishes the default one-second
    # lifetime from increasing multi-second suppression without flooding peers.
    for tick in range(49):
        delay = start + tick * 0.25 - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        for label, host, port, name in states:
            before = counts()
            began = time.monotonic()
            query(host, port, "udp", name)
            after = counts()
            row = {
                "server": label,
                "tick": tick,
                "elapsed": began - start,
                "upstream_before": total(before, name),
                "upstream_after": total(after, name),
            }
            rows.append(row)
            print(json.dumps(row), flush=True)
    # Independently verify that persistent A failure does not poison fresh AAAA
    # data. Client CD uses its own identity; its second request must be warm.
    failures = []
    for label, host, port, name in states:
        query(host, port, "udp", name, "AAAA", expected=0)
        query(host, port, "udp", name, cd=True)
        before = counts()
        query(host, port, "udp", name, cd=True)
        if total(counts(), name) != total(before, name):
            failures.append(f"{label}: immediate CD retry emitted traffic")
    with urlopen(Request(AUTHORITY + "/advance", method="POST"), timeout=3):
        pass
    # This bounded recovery observation covers the current defaults only; it is
    # not a universal maximum for implementations choosing longer failure TTLs.
    time.sleep(6.2)
    for label, host, port, name in states:
        query(host, port, "udp", name, expected=0)
        own = [r for r in rows if r["server"] == label]
        epochs = [r for r in own if r["upstream_after"] > r["upstream_before"]]
        times = [r["elapsed"] for r in epochs]
        intervals = [b - a for a, b in zip(times, times[1:])]
        if label == "donna" and (
            len(intervals) < 2 or intervals[1] < intervals[0] + 0.5
        ):
            failures.append(
                f"{label}: persistent failures did not increase retry intervals: {intervals}"
            )
        print(
            json.dumps(
                {
                    "server": label,
                    "retry_epoch_times": times,
                    "retry_intervals": intervals,
                    "upstream_queries_in_window": sum(
                        r["upstream_after"] - r["upstream_before"] for r in own
                    ),
                    "window_seconds": own[-1]["elapsed"],
                    "backoff_observation": "intervals retained; no peer-as-oracle inference",
                }
            ),
            flush=True,
        )
    print(
        json.dumps(
            {
                "result": "FAIL" if failures else "PASS",
                "failures": failures,
                "scope": "12-second persistent SERVFAIL observation, QTYPE/CD isolation, six-second recovery",
            }
        ),
        flush=True,
    )
    if failures:
        raise SystemExit("persistent failure backoff or isolation gate failed")


if __name__ == "__main__":
    main()

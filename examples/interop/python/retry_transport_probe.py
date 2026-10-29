"""Count actual UDP truncations and TCP connection-close retries independently."""

import json
from recursive_cache_probe import SERVERS, ZONE, counts
from resolution_failure_probe import query


def main():
    failures = []
    for label, host, port in SERVERS:
        for protocol in ("udp", "tcp"):
            name = f"tcpdrop-{label}-{protocol}.{ZONE}"
            before = counts()
            query(host, port, protocol, name)
            cold = counts()
            query(host, port, protocol, name)
            warm = counts()
            deltas = {
                wire: cold.get(f"{wire}:{name}/A", 0)
                - before.get(f"{wire}:{name}/A", 0)
                for wire in ("udp", "tcp")
            }
            passed = all(1 <= n <= 3 for n in deltas.values()) and all(
                warm.get(f"{wire}:{name}/A", 0) == cold.get(f"{wire}:{name}/A", 0)
                for wire in ("udp", "tcp")
            )
            row = {
                "server": label,
                "client_protocol": protocol,
                "name": name,
                "cold_wire_transmissions": deltas,
                "warm_wire_transmissions": {
                    wire: warm.get(f"{wire}:{name}/A", 0)
                    - cold.get(f"{wire}:{name}/A", 0)
                    for wire in ("udp", "tcp")
                },
                "passed": passed,
            }
            if not passed:
                failures.append(row)
            print(json.dumps(row), flush=True)
    print(
        json.dumps(
            {
                "result": "FAIL" if failures else "PASS",
                "failures": failures,
                "scope": "UDP-first resolver; does not force direct encrypted or TCP-only upstream mode",
            }
        ),
        flush=True,
    )
    if failures:
        raise SystemExit("wire retry bounds or warm suppression failed")


if __name__ == "__main__":
    main()

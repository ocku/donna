"""Validate a complete documentation report and print its measured tables."""

import json
import math
import statistics
import sys

with open(sys.argv[1]) as source:
    report = json.load(source)
assert report["complete"], "partial run"

if "cli" in report:
    print("| Client | Median ms | p95 ms | Min to max ms |")
    print("| --- | ---: | ---: | ---: |")
    for name, samples in report["cli"]["samples_ms"].items():
        assert len(samples) == 60
        ordered = sorted(samples)
        print(
            f"| {name} | {statistics.median(samples):.3f} | {ordered[math.ceil(0.95 * len(samples)) - 1]:.3f} | {min(samples):.3f} to {max(samples):.3f} |"
        )

for phase in ("authority", "recursive"):
    if phase not in report["arguments"]["phases"]:
        continue
    print("\n" + phase)
    print("| Server | Workload | Median q/s | Min to max q/s | Mean latency, µs |")
    print("| --- | --- | ---: | ---: | ---: |")
    cases = (
        ("positive", "negative", "wildcard")
        if phase == "authority"
        else ("positive", "negative", "cname")
    )
    roles = (
        ("donna", "bind", "knot", "hickory")
        if phase == "authority"
        else ("donna", "bind", "kresd", "hickory")
    )
    assert len(report[phase]) == 12 * report["arguments"]["repeats"]
    for case in cases:
        for name in roles:
            rows = [
                r
                for r in report[phase]
                if r["server"] == name and r["workload"] == case
            ]
            assert len(rows) == report["arguments"]["repeats"]
            assert {r["repeat"] for r in rows} == set(range(len(rows)))
            assert all(
                r["lost"] == 0
                and r["sent"] == r["queries"]
                and r["queries"] > 0
                and r["semantic_pre_post_checks"] == "PASS"
                for r in rows
            )
            if phase == "authority":
                assert all(r["response_body_verified"] for r in rows)
            qps = [r["qps"] for r in rows]
            latency = statistics.median(r["mean_us"] for r in rows)
            print(
                f"| {name} | {case} | {statistics.median(qps):,.0f} | {min(qps):,.0f} to {max(qps):,.0f} | {latency:.1f} |"
            )

if "recursive" in report["arguments"]["phases"]:
    print("\n| Resolver | Cold median ms | Min to max ms |")
    print("| --- | ---: | ---: |")
    assert len(report["cold"]) == 4 * report["arguments"]["cold_repeats"]
    for name in ("donna", "bind", "kresd", "hickory"):
        rows = [r for r in report["cold"] if r["server"] == name]
        assert len(rows) == report["arguments"]["cold_repeats"]
        values = [r["elapsed_ms"] for r in rows]
        print(
            f"| {name} | {statistics.median(values):.3f} | {min(values):.3f} to {max(values):.3f} |"
        )

"""Offline accounting/packet/source replay for the matched service RAM capsule."""

import hashlib
import json
from pathlib import Path
import statistics
import sys

from service_memory_client import check
from service_memory_fixture import fixture


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(root):
    root = Path(root)
    r = json.loads((root / "result.json").read_text())
    assert r["complete"] is True and len(r["rows"]) == 9
    assert (
        r["repetitions"] == 3 and r["samples_per_phase"] == 3 and r["warm_passes"] == 40
    )
    assert {(row["role"], row["trial"]) for row in r["rows"]} == {
        (role, trial) for role in ("donna", "knot", "hickory") for trial in range(3)
    }
    assert len({row["container_id"] for row in r["rows"]}) == 9
    assert all(
        len(row["container_id"]) == 64 and row["started_at"] for row in r["rows"]
    )
    for name, expected in r["artifact_members_sha256"].items():
        assert Path(name).is_absolute() is False and ".." not in Path(name).parts
        assert digest((root / name).read_bytes()) == expected
    for name, expected in r["harness_sha256"].items():
        assert digest((root / "harness" / name).read_bytes()) == expected
    assert (
        digest((root / "memory_authority").read_bytes()) == r["build"]["binary_sha256"]
    )
    assert digest((root / "batched_load").read_bytes()) == r["native_binary_sha256"]
    zone, pool, _ = fixture()
    assert (root / "zone.db").read_bytes() == zone and (
        root / "queries.framed"
    ).read_bytes() == pool
    assert (
        digest(zone) == r["fixture"]["zone_sha256"]
        and digest(pool) == r["fixture"]["query_pool_sha256"]
    )
    references = {}
    for role, expected in r["references"].items():
        data = (root / (role + "-reference.json")).read_bytes()
        assert digest(data) == expected
        references[role] = json.loads(data)
        check(references[role])
    snapshots = 0
    for row in r["rows"]:
        w = row["workload"]
        assert w["passes"] == 40 and len(w["rows"]) == 40
        assert w["responses"] == w["exact_bodies"] == 30720 and w["lost"] == 0
        assert (
            w["response_pool_sha256"] == references[row["role"]]["response_pool_sha256"]
        )
        for native in w["rows"]:
            n = native["native"]
            assert json.loads(native["stdout"]) == n
            assert n["queries"] == n["sent"] == 768 and n["lost"] == 0
            assert n["response_body_verified"] is True and n["outstanding"] == 32
        data = (root / f"{row['role']}-{row['trial']}-post.json").read_bytes()
        assert digest(data) == row["post_capture_sha256"]
        assert json.loads(data) == references[row["role"]]
        assert row["logging"]["before_bytes"] == row["logging"]["after_bytes"]
        assert row["logging"]["before_sha256"] == row["logging"]["after_sha256"]
        for phase in ("idle", "warm"):
            assert len(row[phase]) == 3
            for s in row[phase]:
                snapshots += 1
                assert (
                    s["schema"] == 1
                    and s["ended_monotonic_ns"] >= s["started_monotonic_ns"]
                )
                assert s["service_root_pid"] == 1 and s["service_cgroup"].endswith(
                    "/" + row["container_id"]
                )
                pids = [p["pid"] for p in s["processes"]]
                assert (
                    len(pids) == len(set(pids))
                    and 1 in pids
                    and s["observer"]["pid"] not in pids
                )
                assert s["observer"]["charged_to_service"] is False
                assert s["observer"]["cgroup"] != s["service_cgroup"]
                assert not s["observer"]["cgroup"].startswith(s["service_cgroup"] + "/")
                totals, roles = {}, {}
                for p in s["processes"]:
                    raw = p["rollup_bytes"]
                    expected = dict(
                        rss_bytes=raw["Rss"],
                        pss_bytes=raw["Pss"],
                        private_clean_dirty_bytes=raw["Private_Clean"]
                        + raw["Private_Dirty"],
                        shared_clean_dirty_bytes=raw["Shared_Clean"]
                        + raw["Shared_Dirty"],
                        swap_bytes=raw.get("Swap", 0),
                    )
                    assert (
                        p["metrics"] == expected
                        and p["threads"] > 0
                        and p["start_ticks"] > 0
                    )
                    for k, v in expected.items():
                        totals[k] = totals.get(k, 0) + v
                        role = roles.setdefault(p["role"], {})
                        role[k] = role.get(k, 0) + v
                assert (
                    totals == s["process_totals"]
                    and roles == s["process_totals_by_role"]
                )
                for edge in ("cgroup_before", "cgroup_after"):
                    c = s[edge]
                    assert c["lifetime_peak_bytes"] >= c["current_bytes"] >= 0
                    assert (
                        c["events"].get("oom", 0) == c["events"].get("oom_kill", 0) == 0
                    )
                    assert c["limit"] == str(256 * 1024 * 1024)
    for role in ("donna", "knot", "hickory"):
        for phase in ("idle", "warm"):
            samples = [
                s for row in r["rows"] if row["role"] == role for s in row[phase]
            ]
            metrics = {
                k: [s["process_totals"][k] for s in samples]
                for k in samples[0]["process_totals"]
            }
            metrics.update(
                cgroup_current_bytes=[
                    s["cgroup_after"]["current_bytes"] for s in samples
                ],
                cgroup_lifetime_peak_bytes=[
                    s["cgroup_after"]["lifetime_peak_bytes"] for s in samples
                ],
            )
            expected = {
                k: dict(median=statistics.median(v), minimum=min(v), maximum=max(v))
                for k, v in metrics.items()
            }
            assert expected == r["summary"][role][phase]
    return dict(
        complete=True,
        processes=9,
        snapshots=snapshots,
        semantic_reference_packets=2304,
        post_packets=6912,
        exact_warm_replies=276480,
        lost=0,
        network="none",
        scope="Retained evidence consistency and explicit fixture semantics; no reconstruction of past live kernel state",
    )


if __name__ == "__main__":
    print(json.dumps(verify(sys.argv[1])))

"""Create a synthetic service-memory capsule for verifier fault injection.

No binaries are executed and no kernel accounting or performance is measured.
"""

import copy
import hashlib
import json

import dns.flags
import dns.message
import dns.rrset

from service_memory_fixture import fixture, query

ROLES = ("donna", "knot", "hickory")
REPETITIONS = 3
SAMPLES = 3
WARM_PASSES = 40
QUERY_COUNT = 768


def digest(data):
    return hashlib.sha256(data).hexdigest()


def references():
    zone, pool, cases = fixture()
    packets, replies = [], []
    for case in cases:
        qwire = query(case["name"], case["kind"])
        response = dns.message.make_response(dns.message.from_wire(qwire))
        response.flags = dns.flags.QR | dns.flags.AA
        response.answer.append(
            dns.rrset.from_text(case["name"], 300, "IN", case["kind"], case["expected"])
        )
        rwire = response.to_wire()
        packets.append(dict(query=qwire.hex(), response=rwire.hex()))
        replies.append(len(rwire).to_bytes(2, "big") + rwire)
    return dict(
        zone_sha256=digest(zone),
        query_pool_sha256=digest(pool),
        response_pool_sha256=digest(b"".join(replies)),
        packets=packets,
    )


def snapshot(container_id):
    raw = dict(
        Rss=1000,
        Pss=600,
        Private_Clean=100,
        Private_Dirty=100,
        Shared_Clean=300,
        Shared_Dirty=400,
        Swap=0,
    )
    metrics = dict(
        rss_bytes=1000,
        pss_bytes=600,
        private_clean_dirty_bytes=200,
        shared_clean_dirty_bytes=700,
        swap_bytes=0,
    )
    cgroup = dict(
        current_bytes=2000,
        lifetime_peak_bytes=3000,
        events=dict(oom=0, oom_kill=0),
        limit=str(256 * 1024 * 1024),
    )
    return dict(
        schema=1,
        started_monotonic_ns=1,
        ended_monotonic_ns=2,
        service_root_pid=1,
        service_cgroup="/service/" + container_id,
        observer=dict(pid=2, charged_to_service=False, cgroup="/observer"),
        processes=[
            dict(
                pid=1,
                role="service",
                rollup_bytes=raw,
                metrics=metrics,
                threads=1,
                start_ticks=1,
            )
        ],
        process_totals=metrics,
        process_totals_by_role=dict(service=metrics),
        cgroup_before=copy.deepcopy(cgroup),
        cgroup_after=cgroup,
    )


def write_capsule(root):
    root.mkdir(parents=True, exist_ok=True)
    zone, pool, _ = fixture()
    files = {
        "zone.db": zone,
        "queries.framed": pool,
        "memory_authority": b"synthetic binary identity; never executed",
        "batched_load": b"synthetic load identity; never executed",
        "harness/model.py": b"# synthetic oracle model\n",
    }
    reference = references()
    reference_bytes = json.dumps(reference).encode()
    rows, summary = [], {}
    for role in ROLES:
        files[role + "-reference.json"] = reference_bytes
        for trial in range(REPETITIONS):
            files[f"{role}-{trial}-post.json"] = reference_bytes
            container_id = digest(f"model {role} {trial}".encode())
            native = dict(
                queries=QUERY_COUNT,
                sent=QUERY_COUNT,
                lost=0,
                response_body_verified=True,
                outstanding=32,
            )
            workload = dict(
                passes=WARM_PASSES,
                responses=QUERY_COUNT * WARM_PASSES,
                exact_bodies=QUERY_COUNT * WARM_PASSES,
                lost=0,
                response_pool_sha256=reference["response_pool_sha256"],
                rows=[
                    dict(native=copy.deepcopy(native), stdout=json.dumps(native))
                    for _ in range(WARM_PASSES)
                ],
            )
            sample = snapshot(container_id)
            rows.append(
                dict(
                    role=role,
                    trial=trial,
                    container_id=container_id,
                    started_at="synthetic model; no service was started",
                    workload=workload,
                    post_capture_sha256=digest(reference_bytes),
                    logging=dict(
                        before_bytes=0,
                        after_bytes=0,
                        before_sha256=digest(b""),
                        after_sha256=digest(b""),
                    ),
                    idle=[copy.deepcopy(sample) for _ in range(SAMPLES)],
                    warm=[copy.deepcopy(sample) for _ in range(SAMPLES)],
                )
            )
        metrics = dict(
            sample["process_totals"],
            cgroup_current_bytes=2000,
            cgroup_lifetime_peak_bytes=3000,
        )
        expected = {
            name: dict(median=value, minimum=value, maximum=value)
            for name, value in metrics.items()
        }
        summary[role] = dict(idle=copy.deepcopy(expected), warm=expected)
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    record = dict(
        complete=True,
        repetitions=REPETITIONS,
        samples_per_phase=SAMPLES,
        warm_passes=WARM_PASSES,
        rows=rows,
        summary=summary,
        artifact_members_sha256={name: digest(data) for name, data in files.items()},
        harness_sha256={"model.py": digest(files["harness/model.py"])},
        build=dict(binary_sha256=digest(files["memory_authority"])),
        native_binary_sha256=digest(files["batched_load"]),
        fixture=dict(zone_sha256=digest(zone), query_pool_sha256=digest(pool)),
        references={role: digest(reference_bytes) for role in ROLES},
    )
    (root / "result.json").write_text(json.dumps(record))

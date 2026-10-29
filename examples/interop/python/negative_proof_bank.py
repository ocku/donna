"""Freeze authenticated denial availability before timing; receipts cannot renew it."""

from negative_evidence import NegativeVerifier
from negative_refresh import NegativeRefreshes


def clock_domain(captures, native=None):
    assert captures
    offsets = [
        capture["checked_at"] - capture["received_monotonic_ns"] / 1e9
        for capture in captures
    ]
    assert all(
        a["received_monotonic_ns"] <= b["received_monotonic_ns"]
        for a, b in zip(captures, captures[1:])
    )
    if native is not None:
        offsets.extend(
            [
                native["started_unix_seconds"] - native["started_monotonic_seconds"],
                native["ended_unix_seconds"] - native["ended_monotonic_seconds"],
            ]
        )
    spread = max(offsets) - min(offsets)
    assert spread < 0.05, "preload/native clock offsets are discontinuous"
    return dict(
        offset_spread_seconds=spread,
        ttl_clock="shared Linux CLOCK_MONOTONIC",
        signature_clock="per-receive wall time",
    )


def freeze(public, captures, witnesses):
    assert captures
    clock_domain(captures)
    questions = [
        (capture["case"]["name"], capture["case"]["rtype"]) for capture in captures
    ]
    assert len(questions) == len(set(questions)), (
        "preload must contain distinct questions"
    )
    verifier = NegativeVerifier(public, captures[0]["checked_at"], frozen=True)
    verifier.refreshes = NegativeRefreshes(
        verifier.oracle, witnesses, [capture["case"] for capture in captures]
    )
    for capture in captures:
        verifier.verify(capture["case"], capture)
    return verifier.summary()

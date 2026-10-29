"""Bind cache-lifetime renewal to retained owner/type upstream query witnesses."""

from datetime import datetime, timezone
import re


def events(before, after, address):
    old, new = before["leaf"], after["leaf"]
    assert new.startswith(old), "authority log changed before its checkpoint"
    pattern = (
        r"^(\d\d-\w{3}-\d{4} \d\d:\d\d:\d\d\.\d{3}).*? "
        + re.escape(address)
        + r"#.*?query: (\S+) IN (\S+)"
    )
    rows = []
    for stamp, name, kind in re.findall(pattern, new[len(old) :], re.MULTILINE):
        when = (
            datetime.strptime(stamp, "%d-%b-%Y %H:%M:%S.%f")
            .replace(tzinfo=timezone.utc)
            .timestamp()
        )
        rows.append(
            dict(checked_at=when, name=name.lower().rstrip(".") + ".", rtype=kind)
        )
    assert all(a["checked_at"] <= b["checked_at"] for a, b in zip(rows, rows[1:]))
    return rows


class Refreshes:
    def __init__(self, witnesses):
        self.events = witnesses
        self.used = {}
        self.upper = {}

    def renew(
        self, identity, rr, case, when, monotonic_ns, original_ttl, expiration, deadline
    ):
        import dns.rdatatype

        name, kind = rr.name.to_text().lower(), dns.rdatatype.to_text(rr.rdtype)
        for index in range(self.used.get(identity, -1) + 1, len(self.events)):
            event = self.events[index]
            if event["checked_at"] > when:
                break
            self.used[identity] = index
            exact = event["name"] == name and event["rtype"] in (kind, "ANY")
            alias = (
                kind == "DNAME"
                and case["kind"] == "dname"
                and event["name"] == case["name"]
                and event["rtype"] in (case["rtype"], "ANY")
            )
            if exact or alias:
                # The controlled authority serves this immutable signed RRset.
                # A logged request bounds a reacquisition's earliest lifetime;
                # it does not waive signature, data, or receive-time checks.
                upper = min(original_ttl, expiration - event["checked_at"])
                renewed = monotonic_ns + round(
                    (event["checked_at"] - when + upper) * 1e9
                )
                self.upper[identity] = max(self.upper.get(identity, 0), renewed)
        # Concurrent replies may still belong to the older generation. A
        # shorter old reply cannot erase the newer, witnessed acquisition
        # ceiling; that ceiling remains fixed at the upstream event's time.
        upper = self.upper.get(identity)
        return max(deadline or 0, upper) if upper is not None else deadline

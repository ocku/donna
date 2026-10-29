"""Negative proof renewal requires a relevant, retained negative query witness."""


class NegativeRefreshes:
    def __init__(self, oracle, witnesses, cases):
        self.oracle, self.events, self.used, self.upper = oracle, witnesses, {}, {}
        self.cases = {
            (case["name"].lower(), case["rtype"]): case
            for case in cases
            if case["kind"] not in ("positive", "insecure-positive")
        }

    def case_for(self, event):
        import dns.name
        import dns.rdatatype

        case = self.cases.get((event["name"], event["rtype"]))
        if case is not None:
            return case
        if event["rtype"] not in ("A", "AAAA", "NS", "DS"):
            return None
        name = dns.name.from_text(event["name"])
        if not any(
            dns.name.from_text(item["name"]).is_subdomain(name)
            for item in self.cases.values()
        ):
            return None
        from negative_denial import APEX

        if not name.is_subdomain(APEX):
            return None
        kind = "nx" if name not in self.oracle.names else "nodata"
        case = dict(name=event["name"], rtype=event["rtype"], kind=kind)
        try:
            self.oracle.expected(case)
        except AssertionError:
            return None
        return case

    def renew(self, identity, rr, when, mono, ttl, expiration, deadline):
        for index in range(self.used.get(identity, -1) + 1, len(self.events)):
            event = self.events[index]
            if event["checked_at"] > when:
                break
            self.used[identity] = index
            case = self.case_for(event)
            if case is None or not self.oracle.relevant(case, rr):
                continue
            bound = min(ttl, expiration - event["checked_at"])
            renewed = mono + round((event["checked_at"] - when + bound) * 1e9)
            self.upper[identity] = max(self.upper.get(identity, 0), renewed)
        upper = self.upper.get(identity)
        return max(deadline or 0, upper) if upper is not None else deadline

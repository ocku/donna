"""RFC-based unsigned authority expectations, independent of DNS client libraries."""

from dataclasses import dataclass

APEX = "example.test."


@dataclass(frozen=True)
class Case:
    name: str
    qtype: str
    rcode: int = 0
    answer: tuple = ()
    negative: bool = False
    referral: bool = False


def record(owner, kind, value):
    return (owner.lower(), kind, value.lower())


def positive(name, value="192.0.2.80"):
    return Case(name, "A", answer=(record(name, "A", value),))


def negative(name, qtype="A", rcode=0, alias=None):
    answer = () if alias is None else (record(name, "CNAME", alias),)
    return Case(name, qtype, rcode, answer, True)


# Existing nodes, including empty nonterminals, stop wildcard search. Asterisks
# are literal labels after the leftmost label; synthesis never removes them.
CASES = (
    positive("random.example.test."),
    positive("multi.label.example.test."),
    positive("*.example.test."),
    negative("random.example.test.", "AAAA"),
    negative("branch.example.test."),
    negative("missing.branch.example.test.", rcode=3),
    negative("ghost.*.example.test.", rcode=3),
    negative("*.*.example.test.", rcode=3),
    negative("m.alias.example.test.", rcode=3, alias="missing.branch.example.test."),
    Case(
        "m.alias.example.test.",
        "CNAME",
        answer=(
            record("m.alias.example.test.", "CNAME", "missing.branch.example.test."),
        ),
    ),
    negative("m.alias-empty.example.test.", alias="branch.example.test."),
    negative("m.emptywild.example.test."),
    positive("m.*.*.nested.example.test.", "192.0.2.82"),
    negative("m.*.*.*.nested.example.test.", rcode=3),
    negative("m.*.nested.example.test."),
    Case("cut.example.test.", "A", referral=True),
    Case("host.cut.example.test.", "A", referral=True),
    Case("*.cut.example.test.", "A", referral=True),
    Case("host.cut.example.test.", "DS", referral=True),
    negative("cut.example.test.", "DS"),
    Case(
        "outside.alias.example.test.",
        "A",
        answer=(record("outside.alias.example.test.", "CNAME", "outside.invalid."),),
    ),
)


def validate(case, response):
    """Validate a normalized reply; callers separately correlate wire questions.

    authority SOAs are (owner, class, ttl, minimum). Answers omit TTL, which is
    independent per RRset. Optional positive authority/additional data is free.
    """
    assert response["rcode"] == case.rcode, "wrong terminal RCODE"
    assert response["aa"] == (not case.referral) and not response["tc"], (
        "wrong authority/truncation flags"
    )
    assert sorted(response["answer"]) == sorted(case.answer), (
        "wrong answer data/owner or extra RR"
    )
    if case.referral:
        assert response["soas"] == [], (
            "referral must not claim authoritative negative data"
        )
        assert response["nameservers"] == [
            ("cut.example.test.", "IN", "ns.cut.example.test.")
        ], "wrong referral NS"
        assert ("ns.cut.example.test.", "IN", "A", "192.0.2.54") in response[
            "additional"
        ], "missing in-domain glue"
    if case.negative:
        soas = response["soas"]
        assert len(soas) == 1, "negative reply must contain one zone SOA"
        owner, rdclass, ttl, minimum = soas[0]
        assert owner == APEX and rdclass == "IN", "wrong terminal SOA scope/class"
        assert ttl == 30 and minimum == 30, "negative TTL must be min(SOA TTL, MINIMUM)"

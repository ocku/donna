"""RFC-based logical-name visibility gates, independent of DNS libraries."""


def expected_rcode(variant, location):
    return (
        0
        if variant == "wildcard"
        or (location == "owner" and variant in ("owner", "descendant"))
        else 3
    )


def validate(variant, location, kind, name, response):
    expected = expected_rcode(variant, location)
    assert response["rcode"] == expected, "wrong logical existence RCODE"
    assert response["aa"] and not response["tc"], (
        "authoritative complete response required"
    )
    answers = response["answer"]
    if expected == 3:
        assert not answers, "metadata-only/nonexistent name leaked answer data"
    if expected == 3 or not answers:
        assert response["soas"] == [("example.test.", "IN", 30, 30)], (
            "negative SOA scope/lifetime missing"
        )
    if variant == "wildcard":
        assert not any(rr[1] == "NSEC3" for rr in answers), (
            "hashed metadata blocked wildcard selection"
        )
        if kind in ("A", "ANY"):
            assert (name.lower(), "A", "IN", "192.0.2.89") in answers, (
                "missing expanded wildcard A"
            )
        elif kind == "NSEC3":
            assert not answers, "wildcard A cannot synthesize NSEC3 data"
        elif kind == "RRSIG":
            assert response["signatures"] and all(
                covered == 1 and labels == 2
                for covered, labels in response["signatures"]
            ), "wrong wildcard RRSIG source"
    if variant == "owner" and location == "owner" and kind in ("A", "ANY"):
        assert (name.lower(), "A", "IN", "192.0.2.88") in answers, (
            "ordinary owner data disappeared"
        )
    if variant == "descendant" and location == "owner" and kind == "A":
        assert not answers, "ordinary descendant creates an empty original parent"

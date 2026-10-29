"""Pure response and counter checks for the short-lived CNAME fixture."""


def validate(response, rcode, answer):
    assert response["rcode"] == rcode and response["answer"] == answer, "wrong response"
    flags = response["flags"]
    assert flags & 0x80 and flags & 0x100, "recursive RD/RA required"
    assert not flags & (0x400 | 0x200 | 0x20), "unexpected AA/TC/AD"
    assert all(value == 1 for value in response["classes"]), "wrong record class"
    if rcode == 3:
        soas = response["soas"]
        assert len(soas) == 1 and soas[0][0] == "example.test.", "wrong negative SOA"
        assert 0 < soas[0][1] <= 12 and soas[0][2] == 12, (
            "old negative must still be live"
        )


def validate_transition(before, after, final_old):
    assert before["alias"] > 0 and before["old"] > 0, (
        "cold questions did not reach authority"
    )
    assert after["alias"] > before["alias"], "expired alias not reacquired"
    assert after["old"] == before["old"] == final_old, (
        "live terminal negative was not reused"
    )

"""Independent normalized cache-reply gates; standard library only."""


def total(snapshot, name):
    return sum(value for key, value in snapshot.items() if key.startswith(name + "/"))


def validate(kind, rcode, answers, response):
    assert response["rcode"] == rcode, "wrong terminal RCODE"
    flags = response["flags"]
    assert flags & 0x80 and flags & 0x100, "recursive RD/RA required"
    assert not flags & (0x400 | 0x200 | 0x20), "unexpected AA/TC/AD"
    assert response["answer"] == answers, "wrong answer data/owner/order"
    assert all(value == 1 for value in response["classes"]), "wrong record class"
    if rcode == 3 or not answers or (answers[-1][1] == "CNAME" and kind != "CNAME"):
        soas = response["soas"]
        assert len(soas) == 1, "one negative SOA required"
        owner, ttl, minimum = soas[0]
        assert owner == "example.test.", "wrong negative SOA zone"
        assert 0 <= ttl <= 6 and minimum == 6, "wrong negative lifetime"

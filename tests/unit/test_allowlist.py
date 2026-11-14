from common.db.migrate import connect
from services.decision.allowlist import Allowlist


def _conn(*addresses):
    conn = connect(":memory:")
    for a in addresses:
        conn.execute("INSERT INTO allowlist_entry (address) VALUES (?)", (a,))
    conn.commit()
    return conn


def test_exact_ip_and_cidr_match():
    al = Allowlist(_conn("192.168.1.1", "10.0.5.0/24"))
    assert al.contains("192.168.1.1")
    assert al.contains("10.0.5.77")
    assert not al.contains("10.0.6.1")
    assert not al.contains("192.168.1.2")


def test_malformed_entry_and_bad_input_are_ignored():
    al = Allowlist(_conn("not-an-ip", "192.168.1.1"))
    assert al.contains("192.168.1.1")
    assert not al.contains("garbage")
    assert not al.contains("")


def test_ipv4_entry_never_matches_ipv6_address():
    assert not Allowlist(_conn("10.0.0.0/8")).contains("::1")


def test_edits_are_picked_up_after_the_ttl():
    class Clock:
        t = 0.0

        def __call__(self):
            return self.t

    clock = Clock()
    conn = _conn()
    al = Allowlist(conn, ttl_s=5.0, clock=clock)
    assert not al.contains("10.0.0.9")
    conn.execute("INSERT INTO allowlist_entry (address) VALUES ('10.0.0.9')")
    conn.commit()
    assert not al.contains("10.0.0.9")
    clock.t = 5.0
    assert al.contains("10.0.0.9")

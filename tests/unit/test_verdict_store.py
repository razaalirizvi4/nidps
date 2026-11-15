import json

from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.schemas import Action, Layer, Verdict
from services.decision.main import decide_groups
from services.decision.verdict_store import VerdictStore


def _conn():
    conn = connect(":memory:")
    seed_defaults(conn)
    return conn


def _v(action=Action.BLOCK, host="10.0.0.5", flow_id=None, **kw):
    return Verdict(action=action, layers=[Layer.L1_SIGNATURE], explanation="drop rule 42",
                   host_ip=host, flow_id=flow_id, attack_class=kw.get("attack_class"))


def test_alert_and_block_are_stored_with_their_host():
    conn = _conn()
    store = VerdictStore(conn)
    assert store.save(_v(Action.BLOCK, attack_class="DDoS")) is not None
    assert store.save(_v(Action.ALERT)) is not None
    rows = conn.execute(
        "SELECT v.decision, v.layers, v.attack_class, v.explanation, h.ip_address "
        "FROM verdict v JOIN host h USING (host_id) ORDER BY verdict_id"
    ).fetchall()
    assert [r[0] for r in rows] == ["BLOCK", "ALERT"]
    assert json.loads(rows[0][1]) == ["L1"]
    assert rows[0][2:] == ("DDoS", "drop rule 42", "10.0.0.5")
    assert conn.execute("SELECT COUNT(*) FROM host").fetchone()[0] == 1  # host reused


def test_pass_and_hostless_verdicts_are_not_stored():
    conn = _conn()
    store = VerdictStore(conn)
    assert store.save(_v(Action.PASS)) is None
    assert store.save(_v(Action.BLOCK, host=None)) is None
    assert conn.execute("SELECT COUNT(*) FROM verdict").fetchone()[0] == 0


def test_flow_link_only_kept_when_the_flow_exists():
    conn = _conn()
    store = VerdictStore(conn)
    store.save(_v(flow_id="999"))
    store.save(_v(flow_id="not-a-number"))
    assert [r[0] for r in conn.execute("SELECT flow_id FROM verdict")] == [None, None]


def test_a_database_failure_does_not_stop_the_verdict_being_published():
    class Boom:
        def save(self, verdict):
            raise RuntimeError("disk full")

    published = []

    class Engine:
        def decide(self, group):
            from services.decision.engine import Decision
            return Decision(verdict=_v(), host_score=None)

    class Bus:
        def publish(self, stream, message):
            published.append(stream)

    assert decide_groups(Engine(), Bus(), [["g"]], Boom()) == 1
    assert len(published) == 1

import fakeredis

from services.dashboard.sessions import SessionStore


def test_create_then_user_id_for_round_trip():
    store = SessionStore(fakeredis.FakeRedis(decode_responses=True))

    token = store.create(user_id=7)

    assert store.user_id_for(token) == 7


def test_user_id_for_unknown_token_is_none():
    store = SessionStore(fakeredis.FakeRedis(decode_responses=True))

    assert store.user_id_for("not-a-real-token") is None


def test_revoke_invalidates_token():
    store = SessionStore(fakeredis.FakeRedis(decode_responses=True))
    token = store.create(user_id=7)

    store.revoke(token)

    assert store.user_id_for(token) is None


def test_two_sessions_have_different_tokens():
    store = SessionStore(fakeredis.FakeRedis(decode_responses=True))

    assert store.create(user_id=1) != store.create(user_id=1)


def test_user_id_for_refreshes_ttl():
    client = fakeredis.FakeRedis(decode_responses=True)
    store = SessionStore(client, ttl_s=1800)
    token = store.create(user_id=7)

    client.expire(f"nidps:session:{token}", 5)
    store.user_id_for(token)

    assert client.ttl(f"nidps:session:{token}") > 5

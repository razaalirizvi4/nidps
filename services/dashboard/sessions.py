"""Opaque, Redis-backed session tokens (FR-9.1). A sliding TTL means an active admin session never
expires mid-use, but an idle browser tab is logged out after ttl_s of inactivity."""
from __future__ import annotations

import secrets
from typing import Optional

_KEY_PREFIX = "nidps:session:"


class SessionStore:
    def __init__(self, redis_client, ttl_s: int = 1800):
        self._client = redis_client
        self._ttl_s = ttl_s

    def create(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        self._client.set(f"{_KEY_PREFIX}{token}", str(user_id), ex=self._ttl_s)
        return token

    def user_id_for(self, token: str) -> Optional[int]:
        key = f"{_KEY_PREFIX}{token}"
        value = self._client.get(key)
        if value is None:
            return None
        self._client.expire(key, self._ttl_s)
        return int(value)

    def revoke(self, token: str) -> None:
        self._client.delete(f"{_KEY_PREFIX}{token}")

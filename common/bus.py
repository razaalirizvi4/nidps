"""Thin wrapper over Redis Streams so services never touch the redis-py API directly."""
from __future__ import annotations

from typing import Callable

import redis

STREAM_EVIDENCE = "nidps:evidence"
STREAM_VERDICTS = "nidps:verdicts"
STREAM_HEARTBEATS = "nidps:heartbeats"
STREAM_CONFIG_CHANGES = "nidps:config_changes"


class EventBus:
    def __init__(self, client: "redis.Redis"):
        self._client = client

    @classmethod
    def from_url(cls, url: str = "redis://localhost:6379/0") -> "EventBus":
        return cls(redis.Redis.from_url(url, decode_responses=True))

    def publish(self, stream: str, body: str) -> str:
        return self._client.xadd(stream, {"body": body})

    def ensure_group(self, stream: str, group: str) -> None:
        try:
            self._client.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        handler: Callable[[str], None],
        count: int = 10,
        block_ms: int = 1000,
    ) -> None:
        self.ensure_group(stream, group)
        response = self._client.xreadgroup(
            group, consumer, {stream: ">"}, count=count, block=block_ms
        )
        for _stream_name, entries in response or []:
            for entry_id, fields in entries:
                handler(fields["body"])
                self._client.xack(stream, group, entry_id)

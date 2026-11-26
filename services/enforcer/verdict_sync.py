"""Deterministic verdict_id derivation for the 'Verdict dual-write exception' (see the
decision-fusion plan's Global Constraints). Both Enforcer's synchronous verdict insert and the
(later) Event Store's async insert must call this exact function on the same bus envelope's
message_id so their INSERT OR IGNORE writes converge on one row; whichever runs first wins."""
from __future__ import annotations

import uuid


def verdict_id_from_message_id(message_id: str) -> int:
    return uuid.UUID(message_id).int & 0x7FFFFFFFFFFFFFFF

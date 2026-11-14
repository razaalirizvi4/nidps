"""model_package registry (FR-12.2, FR-12.5, NFR-17). Rows are only ever added: activating a
model flips is_active between rows of the same type, and rolling back reactivates the model that
was active before. Nothing is deleted or overwritten, so a bad model can always be undone.

Each activation is written to audit_log (action MODEL_ACTIVATE, old_value = the model it
replaced), which is also where rollback finds the previous model. A rollback is logged as
MODEL_ROLLBACK and is not itself part of that history."""
from __future__ import annotations

import json
from typing import Optional

from common.schemas import utc_now_iso

MODEL_TYPES = ("IFOREST", "RF", "XGB")


class ModelRegistry:
    def __init__(self, conn) -> None:
        self._conn = conn

    def register(
        self,
        model_type: str,
        version: str,
        file_path: str,
        feature_list_hash: str,
        extractor_version: str,
        class_list: Optional[list] = None,
        training_data: Optional[dict] = None,
        metrics: Optional[dict] = None,
    ) -> int:
        """Adds an inactive model_package row. Promoting it to active is a separate, explicit
        activate() call."""
        if model_type not in MODEL_TYPES:
            raise ValueError(f"unknown model type {model_type!r}")
        cur = self._conn.execute(
            """INSERT INTO model_package
                   (model_type, version, file_path, feature_list_hash, extractor_version,
                    class_list, training_data, metrics, is_active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (
                model_type, version, file_path, feature_list_hash, extractor_version,
                json.dumps(class_list) if class_list is not None else None,
                json.dumps(training_data) if training_data is not None else None,
                json.dumps(metrics) if metrics is not None else None,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def _type_of(self, model_id: int) -> str:
        row = self._conn.execute(
            "SELECT model_type FROM model_package WHERE model_id = ?", (model_id,)
        ).fetchone()
        if row is None:
            raise LookupError(f"no model_package row {model_id}")
        return row[0]

    def active_id(self, model_type: str) -> Optional[int]:
        row = self._conn.execute(
            """SELECT model_id FROM model_package WHERE model_type = ? AND is_active = 1
               ORDER BY deployed_at DESC, model_id DESC LIMIT 1""",
            (model_type,),
        ).fetchone()
        return row[0] if row else None

    def activate(
        self, model_id: int, user_id: Optional[int] = None, _action: str = "MODEL_ACTIVATE"
    ) -> None:
        model_type = self._type_of(model_id)
        previous = self.active_id(model_type)
        if previous == model_id:
            return
        # One transaction: there is never a moment with zero or two active models of a type.
        with self._conn:
            self._conn.execute(
                "UPDATE model_package SET is_active = 0 WHERE model_type = ?", (model_type,)
            )
            self._conn.execute(
                "UPDATE model_package SET is_active = 1 WHERE model_id = ?", (model_id,)
            )
            self._conn.execute(
                """INSERT INTO audit_log (user_id, action, target, old_value, new_value, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, _action, model_type, str(previous) if previous is not None else None,
                 str(model_id), utc_now_iso()),
            )

    def rollback(self, model_type: str, user_id: Optional[int] = None) -> int:
        """Reactivates the model that the current active one replaced. Returns its model_id."""
        current = self.active_id(model_type)
        if current is None:
            raise LookupError(f"no active {model_type} model to roll back from")
        row = self._conn.execute(
            """SELECT old_value FROM audit_log
               WHERE action = 'MODEL_ACTIVATE' AND target = ? AND new_value = ?
               ORDER BY audit_id DESC LIMIT 1""",
            (model_type, str(current)),
        ).fetchone()
        if row is None or row[0] is None:
            raise LookupError(f"no earlier {model_type} model recorded to roll back to")
        previous = int(row[0])
        # Logged as MODEL_ROLLBACK so it is not mistaken for history: rolling back twice walks
        # further back instead of undoing the first rollback.
        self.activate(previous, user_id, _action="MODEL_ROLLBACK")
        return previous

    def update_metrics(self, model_id: int, metrics: dict) -> None:
        self._conn.execute(
            "UPDATE model_package SET metrics = ? WHERE model_id = ?",
            (json.dumps(metrics), model_id),
        )
        self._conn.commit()

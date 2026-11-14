"""FR-12.4: refuse a model whose feature set does not match the running extractor. A model
trained on one feature order and scored on another would produce confident nonsense, so the
mismatch has to stop the model from loading rather than show up later as odd scores."""
from __future__ import annotations

from training.feature_schema import current_extractor_version, feature_list_hash


class IncompatibleModel(RuntimeError):
    pass


def verify_compatible(stored_hash: str, stored_extractor_version: str) -> None:
    expected_version = current_extractor_version()
    if stored_extractor_version != expected_version:
        raise IncompatibleModel(
            f"model was built with extractor {stored_extractor_version!r}, "
            f"this device runs {expected_version!r}"
        )
    expected_hash = feature_list_hash()
    if stored_hash != expected_hash:
        raise IncompatibleModel(
            "model feature list does not match the running extractor "
            f"(stored {stored_hash[:12]}..., expected {expected_hash[:12]}...)"
        )


def check_model_package(conn, model_id: int) -> None:
    row = conn.execute(
        "SELECT feature_list_hash, extractor_version FROM model_package WHERE model_id = ?",
        (model_id,),
    ).fetchone()
    if row is None:
        raise LookupError(f"no model_package row {model_id}")
    verify_compatible(row[0], row[1])

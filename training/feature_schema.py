"""FR-12.4: identity of the feature set a model was trained on. The hash covers the ordered
feature names plus the extractor version, so reordering, adding or recomputing a feature changes
it and the runtime can refuse a model that no longer matches the extractor."""
from __future__ import annotations

import hashlib
from typing import Optional, Sequence


def feature_list_hash(feature_names: Optional[Sequence[str]] = None,
                      extractor_version: Optional[str] = None) -> str:
    if feature_names is None:
        from services.flowextract.features import FEATURE_NAMES
        feature_names = FEATURE_NAMES
    if extractor_version is None:
        extractor_version = current_extractor_version()
    payload = "\n".join(feature_names) + "\n" + extractor_version
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def current_extractor_version() -> str:
    from services.flowextract.main import EXTRACTOR_VERSION
    return EXTRACTOR_VERSION

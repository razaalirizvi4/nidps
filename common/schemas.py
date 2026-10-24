"""Shared value types used across every NIDPS service. Fixed by this plan — import these
rather than redefining a Flow/Evidence/Verdict shape in a service's own code."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

SCHEMA_VERSION = "1.0"
FEATURE_COUNT = 78


class Layer(str, enum.Enum):
    L1_SIGNATURE = "L1"
    ARP = "ARP"
    L2_ANOMALY = "L2"
    L3_CLASSIFIER = "L3"
    HOST = "HOST"


class EvidenceType(str, enum.Enum):
    SIGNATURE = "SIGNATURE"
    ANOMALY = "ANOMALY"
    CLASS = "CLASS"
    EXFIL = "EXFIL"
    BEACON = "BEACON"


class Action(str, enum.Enum):
    PASS = "PASS"
    ALERT = "ALERT"
    BLOCK = "BLOCK"


class HealthState(str, enum.Enum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    RECOVERING = "RECOVERING"


class FailureMode(str, enum.Enum):
    FAIL_OPEN = "FAIL_OPEN"
    FAIL_CLOSED = "FAIL_CLOSED"
    DEGRADED = "DEGRADED"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class TLSFingerprint:
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    server_name: Optional[str] = None


@dataclass
class FlowFeatures:
    schema_version: str
    values: list

    def validate(self) -> bool:
        return self.schema_version == SCHEMA_VERSION and len(self.values) == FEATURE_COUNT


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: str
    end_time: str
    is_partial: bool
    features: FlowFeatures
    tls: Optional[TLSFingerprint] = None


@dataclass
class Evidence:
    source: Layer
    flow_id: Optional[str]
    host_ip: str
    kind: EvidenceType
    strength: float
    weight: float
    timestamp: str = field(default_factory=utc_now_iso)
    signature_id: Optional[int] = None
    predicted_class: Optional[str] = None
    confidence: Optional[float] = None
    model_id: Optional[int] = None


@dataclass
class Verdict:
    action: Action
    layers: list
    explanation: str
    flow_id: Optional[str] = None
    host_ip: Optional[str] = None
    attack_class: Optional[str] = None
    timestamp: str = field(default_factory=utc_now_iso)


@dataclass
class ComponentHealth:
    name: str
    state: HealthState
    last_heartbeat: str
    queue_depth: int = 0
    cpu_pct: Optional[float] = None
    mem_mb: Optional[float] = None


@dataclass
class BlockEntry:
    ip: str
    reason: str
    duration_s: int
    offence_count: int
    created_at: str = field(default_factory=utc_now_iso)

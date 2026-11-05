"""Host behaviour anomaly detection: ExfiltrationTracker for per-host outbound data volume analysis."""
import math
from dataclasses import dataclass, field
from typing import Optional

from common.schemas import Evidence, EvidenceType, Layer


EXFIL_RATIO_THRESHOLD: float = 3.0


@dataclass
class FlowObservation:
    """A single flow observation for host behaviour tracking."""
    host_ip: str
    dst_ip: str
    sni: Optional[str]
    ja3: Optional[str]
    fwd_bytes: float
    bwd_bytes: float
    end_time_epoch: float
    is_partial: bool
    is_new_destination: bool


@dataclass
class _ExfilState:
    """Per-host state for ExfiltrationTracker."""
    current_bucket_idx: Optional[int] = None
    current_fwd: float = 0.0
    current_bwd: float = 0.0
    ewma_mean: float = 0.0
    ewma_var: float = 0.0
    initialized: bool = False


class ExfiltrationTracker:
    """Tracks per-host outbound data exfiltration using EWMA-based anomaly detection.

    Uses exponentially weighted moving average (EWMA) to track typical outbound data volumes,
    flags when a single bucket exceeds threshold both in magnitude (multiple standard deviations
    above mean) and ratio (forward/backward ratio >= threshold).
    """

    def __init__(self, ewma_alpha: float, bucket_seconds: int, k_std: float, u_max: Optional[int]):
        """Initialize the exfiltration tracker.

        Args:
            ewma_alpha: EWMA smoothing factor (0 < alpha <= 1)
            bucket_seconds: Time window for aggregating flows (in seconds)
            k_std: Number of standard deviations for threshold (e.g., 2.0 for 2-sigma)
            u_max: Threshold for fast-path detection on partial segments to new destinations.
                   None disables fast-path check.
        """
        self._alpha = ewma_alpha
        self._bucket_seconds = bucket_seconds
        self._k_std = k_std
        self._u_max = u_max
        self._state: dict[str, _ExfilState] = {}

    def observe(self, obs: FlowObservation) -> list[Evidence]:
        """Process a flow observation and detect exfiltration anomalies.

        Returns a list of Evidence objects for detected anomalies (0 or 1 from fast path,
        0 or 1 from bucket finalization, potentially 2 if both fire on same call).
        """
        evidence_list: list[Evidence] = []

        # Fast-path check: immediate flag for suspicious transfers to new destinations
        if (obs.is_partial and self._u_max is not None and
            obs.fwd_bytes > self._u_max and obs.is_new_destination):
            evidence_list.append(Evidence(
                source=Layer.L2_ANOMALY,
                flow_id=None,
                host_ip=obs.host_ip,
                kind=EvidenceType.EXFIL,
                strength=1.0,
                weight=0.0,
            ))

        # Bucket-based EWMA check
        bucket_idx = math.floor(obs.end_time_epoch / self._bucket_seconds)

        # Initialize or retrieve state for this host
        if obs.host_ip not in self._state:
            self._state[obs.host_ip] = _ExfilState()

        state = self._state[obs.host_ip]

        # Handle bucket transition or initialization
        if state.current_bucket_idx is None:
            # First observation for this host
            state.current_bucket_idx = bucket_idx
            state.current_fwd = obs.fwd_bytes
            state.current_bwd = obs.bwd_bytes
        elif state.current_bucket_idx != bucket_idx:
            # Bucket changed: finalize the previous bucket
            b_t = state.current_fwd

            # Check for exfiltration if we have an established baseline
            if state.initialized:
                std = math.sqrt(state.ewma_var)
                threshold = state.ewma_mean + self._k_std * std

                # Both magnitude and ratio must exceed thresholds
                ratio = b_t / max(state.current_bwd, 1.0)
                if b_t > threshold and ratio >= EXFIL_RATIO_THRESHOLD:
                    evidence_list.append(Evidence(
                        source=Layer.L2_ANOMALY,
                        flow_id=None,
                        host_ip=obs.host_ip,
                        kind=EvidenceType.EXFIL,
                        strength=1.0,
                        weight=0.0,
                    ))

            # Update EWMA with the finalized bucket
            ewma_mean_before = state.ewma_mean
            state.ewma_mean = self._alpha * b_t + (1 - self._alpha) * state.ewma_mean
            state.ewma_var = (self._alpha * (b_t - ewma_mean_before) ** 2 +
                              (1 - self._alpha) * state.ewma_var)
            state.initialized = True

            # Start accumulating the new bucket
            state.current_bucket_idx = bucket_idx
            state.current_fwd = obs.fwd_bytes
            state.current_bwd = obs.bwd_bytes
        else:
            # Same bucket: accumulate
            state.current_fwd += obs.fwd_bytes
            state.current_bwd += obs.bwd_bytes

        return evidence_list

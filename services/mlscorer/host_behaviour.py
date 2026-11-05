"""Host behaviour anomaly detection: ExfiltrationTracker for per-host outbound data volume analysis."""
import math
import statistics
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


RARE_JA3_HOST_THRESHOLD: int = 2


class BeaconTracker:
    """Tracks periodic C2 beaconing behavior from hosts using rare JA3 fingerprints.

    Detects hosts that establish connections at suspiciously regular intervals with
    consistent message sizes, a classic signature of botnet or C2 command-and-control
    communication. Flags only if: (1) timing shows low coefficient of variation,
    (2) message sizes show low coefficient of variation, and (3) the JA3 fingerprint
    is rare (used by few distinct hosts).
    """

    def __init__(self, min_connections: int, cv_threshold: float):
        """Initialize the beacon tracker.

        Args:
            min_connections: Minimum number of connections to a group before checking for beaconing.
            cv_threshold: Coefficient of variation threshold for timing and bytes (0 < cv_threshold < 1).
        """
        self._min_connections = min_connections
        self._cv_threshold = cv_threshold
        self._group_history: dict[tuple, list[tuple[float, float]]] = {}
        self._ja3_hosts: dict[str, set[str]] = {}

    def observe(self, obs: FlowObservation) -> Optional[Evidence]:
        """Process a flow observation and detect beaconing patterns.

        Returns Evidence if the flow belongs to a group exhibiting suspicious periodic behavior
        with a rare JA3 fingerprint, otherwise None.
        """
        # Step 1: Record JA3 against host (skip if obs.ja3 is None)
        if obs.ja3 is not None:
            if obs.ja3 not in self._ja3_hosts:
                self._ja3_hosts[obs.ja3] = set()
            self._ja3_hosts[obs.ja3].add(obs.host_ip)

        # Step 2: Determine dst_key (sni if present, else dst_ip) and append to group history
        dst_key = obs.sni if obs.sni else obs.dst_ip
        group_key = (obs.host_ip, dst_key, obs.ja3)

        if group_key not in self._group_history:
            self._group_history[group_key] = []

        total_bytes = obs.fwd_bytes + obs.bwd_bytes
        self._group_history[group_key].append((obs.end_time_epoch, total_bytes))
        history = self._group_history[group_key]

        # Step 3: Check if we have enough connections
        if len(history) < self._min_connections:
            return None

        # Step 4: Compute inter-arrival deltas and CV for timing
        intervals = []
        for i in range(1, len(history)):
            delta = history[i][0] - history[i - 1][0]
            intervals.append(delta)

        # Compute mean of intervals
        mean_interval = sum(intervals) / len(intervals) if intervals else 0.0

        # If mean is 0.0, treat CV as "not low" (return None for this signal)
        if mean_interval == 0.0:
            return None

        # Compute sample standard deviation (ddof=1 for consistency with Welford convention)
        stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv_timing = stdev_interval / mean_interval

        # Step 4b: Compute CV for bytes
        bytes_list = [size for _, size in history]
        mean_bytes = sum(bytes_list) / len(bytes_list)

        # If mean is 0.0, treat CV as "not low" (return None for this signal)
        if mean_bytes == 0.0:
            return None

        # Compute sample standard deviation (ddof=1 for consistency with Welford convention)
        stdev_bytes = statistics.stdev(bytes_list) if len(bytes_list) > 1 else 0.0
        cv_bytes = stdev_bytes / mean_bytes

        # Step 5: Check JA3 rarity (skip entirely if obs.ja3 is None)
        if obs.ja3 is None:
            return None

        ja3_count = len(self._ja3_hosts.get(obs.ja3, set()))
        is_rare = ja3_count <= RARE_JA3_HOST_THRESHOLD

        # Step 6: Report Evidence only when all three conditions are met
        if cv_timing <= self._cv_threshold and cv_bytes <= self._cv_threshold and is_rare:
            return Evidence(
                source=Layer.L2_ANOMALY,
                flow_id=None,
                host_ip=obs.host_ip,
                kind=EvidenceType.BEACON,
                strength=1.0,
                weight=0.0,
            )

        return None

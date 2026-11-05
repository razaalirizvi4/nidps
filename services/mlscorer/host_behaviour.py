"""Host behaviour anomaly detection: ExfiltrationTracker for per-host outbound data volume analysis."""
import math
import statistics
from collections import deque
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
class _ExfilBucket:
    """One host's in-progress totals for a single bucket index."""
    fwd: float = 0.0
    bwd: float = 0.0


@dataclass
class _ExfilState:
    """Per-host state for ExfiltrationTracker."""
    # bucket_idx -> accumulator, for every bucket not yet finalized. Bounded by
    # ExfiltrationTracker._max_open_buckets; see the cap rule.
    open_buckets: dict[int, _ExfilBucket] = field(default_factory=dict)
    ewma_mean: float = 0.0
    ewma_var: float = 0.0
    initialized: bool = False


class ExfiltrationTracker:
    """Tracks per-host outbound data exfiltration using EWMA-based anomaly detection.

    Uses exponentially weighted moving average (EWMA) to track typical outbound data volumes,
    flags when a single bucket exceeds threshold both in magnitude (multiple standard deviations
    above mean) and ratio (forward/backward ratio >= threshold).

    Flow observations for a given host do not necessarily arrive in end_time order --
    concurrent connections on one host are reported independently (on close, on
    active-timeout rollover, or on idle expiry), so the bucket index a host presents to
    observe() can walk backwards as well as forwards. Rather than finalize a bucket the
    instant a different bucket index is seen, this tracker buffers several open buckets per
    host and finalizes a bucket only once a global watermark (the largest end_time seen
    across all hosts) proves no further observation can land in it. See
    .superpowers/sdd/exfil-bucket-watermark-design.md for the full design.
    """

    def __init__(
        self,
        ewma_alpha: float,
        bucket_seconds: int,
        k_std: float,
        u_max: Optional[int],
        idle_timeout_s: int,
    ):
        """Initialize the exfiltration tracker.

        Args:
            ewma_alpha: EWMA smoothing factor (0 < alpha <= 1)
            bucket_seconds: Time window for aggregating flows (in seconds)
            k_std: Number of standard deviations for threshold (e.g., 2.0 for 2-sigma)
            u_max: Threshold for fast-path detection on partial segments to new destinations.
                   None disables fast-path check.
            idle_timeout_s: network.idle_timeout_s -- the maximum number of seconds a
                   reported flow's end_time can lag behind the newest end_time already seen
                   (an expireIdle()-reported flow's end_time is its last_seen). Sizes the
                   grace margin before a bucket is treated as complete. Pass 0 only to
                   assert that observations arrive in end_time order (tests).
        """
        self._alpha = ewma_alpha
        self._bucket_seconds = bucket_seconds
        self._k_std = k_std
        self._u_max = u_max
        self._state: dict[str, _ExfilState] = {}

        self._idle_timeout_s = idle_timeout_s
        self._lag_seconds: float = (
            0.0 if idle_timeout_s <= 0 else idle_timeout_s + bucket_seconds
        )
        self._grace_buckets: int = math.ceil(self._lag_seconds / bucket_seconds)
        self._max_open_buckets: int = self._grace_buckets + 2
        self._stream_max_end_time: Optional[float] = None
        self.dropped_late_observations: int = 0

    def set_u_max(self, u_max: Optional[int]) -> None:
        """Update the fast-path threshold in place.

        Lets a long-lived tracker instance pick up a freshly loaded or recalibrated
        model's u_max without being reconstructed -- e.g. when the model only becomes
        available after a startup retry, or when recalibration later computes a new value.
        """
        self._u_max = u_max

    def observe(self, obs: FlowObservation) -> list[Evidence]:
        """Process a flow observation and detect exfiltration anomalies.

        Returns a list of Evidence objects for detected anomalies: 0 or 1 from the fast
        path, plus 0 or more from bucket finalization (watermark-driven, so more than one
        bucket -- for this host or others -- can finalize on a single call).
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

        # Bucket index of this observation (unchanged formula)
        bucket_idx = math.floor(obs.end_time_epoch / self._bucket_seconds)

        # Per-host state
        if obs.host_ip not in self._state:
            self._state[obs.host_ip] = _ExfilState()
        state = self._state[obs.host_ip]

        # Advance the global watermark, then derive the cutoff
        if self._stream_max_end_time is None or obs.end_time_epoch > self._stream_max_end_time:
            self._stream_max_end_time = obs.end_time_epoch
        cutoff_idx = math.floor((self._stream_max_end_time - self._lag_seconds) / self._bucket_seconds)

        # Is this observation too late to place?
        if bucket_idx < cutoff_idx:
            self.dropped_late_observations += 1
            return evidence_list  # fast-path evidence, if any, is still returned

        # Accumulate into the right bucket, creating it if needed
        if bucket_idx not in state.open_buckets:
            state.open_buckets[bucket_idx] = _ExfilBucket()
        bucket = state.open_buckets[bucket_idx]
        bucket.fwd += obs.fwd_bytes
        bucket.bwd += obs.bwd_bytes

        # The watermark is global (§4.2), so the cutoff it produces must be applied to
        # EVERY host's open_buckets -- including hosts that have gone dark and will never
        # call observe() again. self._state is not mutated here (only the inner dicts are),
        # and obs.host_ip was already inserted above, so iterating it is safe.
        for h_ip, h_state in self._state.items():  # insertion order: deterministic
            # Drain every bucket the cutoff has passed, ascending
            for idx in sorted(h_state.open_buckets):
                if idx >= cutoff_idx:
                    break  # sorted: nothing later can qualify either
                ev = self._finalize_bucket(h_ip, h_state, h_state.open_buckets.pop(idx))
                if ev is not None:
                    evidence_list.append(ev)

            # Hard memory cap (defensive; unreachable via the drain's invariant)
            while len(h_state.open_buckets) > self._max_open_buckets:
                idx = min(h_state.open_buckets)
                ev = self._finalize_bucket(h_ip, h_state, h_state.open_buckets.pop(idx))
                if ev is not None:
                    evidence_list.append(ev)

        return evidence_list

    def _finalize_bucket(
        self, host_ip: str, state: _ExfilState, bucket: _ExfilBucket
    ) -> Optional[Evidence]:
        """Finalize one bucket: run the magnitude+ratio check, then fold it into the EWMA.

        Verbatim lift of the pre-watermark finalize logic: same max(bwd, 1.0) zero guard,
        same EXFIL_RATIO_THRESHOLD gate, same "no check until a baseline exists" rule, same
        pre-update mean in the variance term.
        """
        b_t = bucket.fwd
        result: Optional[Evidence] = None

        if state.initialized:
            std = math.sqrt(state.ewma_var)
            threshold = state.ewma_mean + self._k_std * std

            ratio = b_t / max(bucket.bwd, 1.0)
            if b_t > threshold and ratio >= EXFIL_RATIO_THRESHOLD:
                result = Evidence(
                    source=Layer.L2_ANOMALY,
                    flow_id=None,
                    host_ip=host_ip,
                    kind=EvidenceType.EXFIL,
                    strength=1.0,
                    weight=0.0,
                )

        ewma_mean_before = state.ewma_mean
        state.ewma_mean = self._alpha * b_t + (1 - self._alpha) * state.ewma_mean
        state.ewma_var = (self._alpha * (b_t - ewma_mean_before) ** 2 +
                          (1 - self._alpha) * state.ewma_var)
        state.initialized = True

        return result

    def flush_all(self) -> list[Evidence]:
        """Finalize every open bucket for every host, in ascending bucket order per host.

        Caller contract: only call this when no further observation can arrive for the
        buckets currently buffered -- i.e. when the FLOW_READY stream has been quiescent for
        at least network.idle_timeout_s + 2 * exfil.bucket_seconds wall-clock seconds, or at
        shutdown. Calling it while the stream is live would finalize partial buckets, which
        is the bug this class's watermark exists to avoid.
        """
        evidence_list: list[Evidence] = []
        for host_ip, state in self._state.items():
            for idx in sorted(state.open_buckets):
                ev = self._finalize_bucket(host_ip, state, state.open_buckets[idx])
                if ev is not None:
                    evidence_list.append(ev)
            state.open_buckets.clear()
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
        # Each group's history is a bounded ring: group keys include attacker-controlled
        # sni/ja3 strings, so an unbounded list per group would grow without limit and make
        # the per-observe CV scan O(n) (O(n^2) cumulative) for a long-lived group. A window
        # of a few times min_connections is all the CV computation ever needs.
        self._history_maxlen = max(min_connections * 4, 32)
        self._group_history: dict[tuple, deque[tuple[float, float]]] = {}
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
            self._group_history[group_key] = deque(maxlen=self._history_maxlen)

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


class HostBehaviourTracker:
    """Composition of exfiltration and beacon trackers for host behaviour anomaly detection.

    Combines results from both ExfiltrationTracker and BeaconTracker into a single
    observation interface.
    """

    def __init__(self, exfil: ExfiltrationTracker, beacon: BeaconTracker):
        """Initialize the host behaviour tracker.

        Args:
            exfil: ExfiltrationTracker instance for volume-based anomaly detection.
            beacon: BeaconTracker instance for periodic beaconing detection.
        """
        self._exfil = exfil
        self._beacon = beacon

    def observe(self, obs: FlowObservation) -> list[Evidence]:
        """Process a flow observation using both trackers.

        Concatenates results from exfiltration tracking with beaconing tracking.

        Args:
            obs: Flow observation to process.

        Returns:
            Combined list of Evidence objects from both trackers (0 to 2+ items).
        """
        evidence_list = self._exfil.observe(obs)
        beacon_result = self._beacon.observe(obs)
        if beacon_result is not None:
            evidence_list.append(beacon_result)
        return evidence_list

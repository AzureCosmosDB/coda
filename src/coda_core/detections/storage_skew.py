"""DX-015: Partition storage skew.

A skewed partition key concentrates *data* (not just RU) on a subset of physical partitions, so one
partition holds far more storage than its siblings. Unlike DX-006 (hot partition = throughput
saturation/throttling), the risk here is **storage capacity**: a physical partition has a hard ~50 GiB
ceiling, and a single *logical* partition key has a hard ~20 GiB ceiling. A physical partition that is
both large and unable to split (because its data is concentrated in one logical key) trends toward a
**hard write-failure wall** that adding RU cannot fix — the only remedy is a better partition key.

Detection signal: per-physical-partition storage from Azure Monitor ``PhysicalPartitionSizeInfo``
(Bytes), split by ``PhysicalPartitionId``, reduced to each partition's peak size over the window.
Storage skew exists when partitions are **imbalanced** (the coolest holds materially less than the
busiest) — imbalance is the proxy for partition-key concentration, since balanced large partitions
simply split as they grow (which is healthy and needs no action). Severity scales with how close the
busiest partition is to the physical ceiling: the nearer the 50 GiB limit, the more imminent the
split-wall / write-failure risk.

This is a distinct risk model from DX-006 (which is throughput, not storage); the two share only the
bad-partition-key root cause. v1 detects **physical-partition storage skew** from Azure Monitor (no
Log Analytics dependency). Identifying the specific oversized **logical key** and its 20 GiB headroom
needs Log Analytics ``CDBPartitionKeyStatistics`` and is a follow-up. Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.arm import ThroughputOffer
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricSeries, TimeWindow
from coda_core.sufficiency import evaluate_age

# Verified Cosmos DB limits (Microsoft Learn, partitioning-overview): a physical partition holds up to
# 50 GiB of storage before the platform splits it; a single logical partition key is hard-capped at
# 20 GiB, after which writes to that key are blocked. These anchor the severity model and remediation.
PHYSICAL_PARTITION_LIMIT_BYTES = 50 * 1024**3
LOGICAL_PARTITION_LIMIT_BYTES = 20 * 1024**3

# Storage is a slow-moving level; a 7-day window with a 1-day age floor is plenty.
PRODUCTION_WINDOW_DAYS = 7
AGE_FLOOR = timedelta(days=1)


def production_window(now: datetime | None = None) -> TimeWindow:
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=PRODUCTION_WINDOW_DAYS), anchor, timedelta(hours=1))


@dataclass(frozen=True)
class StorageSkewSignal:
    """Per-physical-partition storage picture for one container."""

    partition_count: int
    max_bytes: float          # busiest partition's peak storage
    min_bytes: float          # coolest partition's peak storage
    mean_bytes: float
    skew_ratio: float         # max / mean — descriptive context only, NOT the trigger
    balance_ratio: float      # min / max — < balance_floor means imbalanced (the trigger)
    busiest_pct_of_limit: float  # max_bytes as % of the 50 GiB physical ceiling (drives severity)

    def as_dict(self) -> dict:
        return asdict(self)


def _partition_peak_bytes(series: MetricSeries) -> float:
    """A partition's storage is a level, not a rate — take its peak over the window."""
    vals = series.values()
    return max(vals) if vals else 0.0


def storage_skew(per_partition: dict[str, MetricSeries]) -> tuple[int, float, float, float]:
    """Return (count, max_bytes, min_bytes, mean_bytes) of per-partition peak storage.

    Keeps **every** partition that reported data — including a genuinely empty (0-byte) one, which is
    itself extreme skew (e.g. 40 GiB vs 0). Only partitions with no data points at all are excluded
    (``if s.values()``), so a missing metric isn't mistaken for an empty partition.
    """
    sizes = [
        _partition_peak_bytes(s) for s in per_partition.values() if s.values()
    ]
    if not sizes:
        return 0, 0.0, 0.0, 0.0
    return len(sizes), max(sizes), min(sizes), sum(sizes) / len(sizes)


@dataclass(frozen=True)
class StorageSkewConfig:
    """Tunable knobs grounded in the verified 50 GiB physical-partition ceiling."""

    min_busiest_bytes: float = 1.0 * 1024**3   # below this, storage is immaterial — no finding
    balance_floor: float = 0.7                 # coolest < this fraction of busiest = imbalanced
    high_pct_of_limit: float = 80.0            # busiest >= 80% of 50 GiB (40 GiB) -> high
    medium_pct_of_limit: float = 50.0          # busiest >= 50% of 50 GiB (25 GiB) -> medium


@dataclass(frozen=True)
class StorageSkewVerdict:
    is_storage_skew: bool
    partition_count: int
    max_bytes: float
    min_bytes: float
    skew_ratio: float
    busiest_pct_of_limit: float
    # storage_skew | uniform_storage | too_small | single_partition | insufficient_data
    root_cause: str
    severity: str  # high | medium | low | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def classify(
    signal: StorageSkewSignal, config: StorageSkewConfig | None = None
) -> StorageSkewVerdict:
    """Map a per-partition storage-skew signal to a verdict."""
    cfg = config or StorageSkewConfig()

    def verdict(**kw) -> StorageSkewVerdict:
        base = dict(
            is_storage_skew=False, partition_count=signal.partition_count,
            max_bytes=round(signal.max_bytes, 1), min_bytes=round(signal.min_bytes, 1),
            skew_ratio=round(signal.skew_ratio, 2),
            busiest_pct_of_limit=round(signal.busiest_pct_of_limit, 1),
            root_cause="uniform_storage", severity="none", recommended_action="",
            methodology={
                "thresholds": {
                    "min_busiest_gib": round(cfg.min_busiest_bytes / 1024**3, 2),
                    "balance_floor": cfg.balance_floor,
                    "high_pct_of_limit": cfg.high_pct_of_limit,
                    "medium_pct_of_limit": cfg.medium_pct_of_limit,
                },
                "physical_partition_limit_gib": PHYSICAL_PARTITION_LIMIT_BYTES // 1024**3,
                "logical_partition_limit_gib": LOGICAL_PARTITION_LIMIT_BYTES // 1024**3,
                "balance_ratio": round(signal.balance_ratio, 3),
            },
        )
        base.update(kw)
        return StorageSkewVerdict(**base)

    if signal.partition_count == 0:
        return verdict(root_cause="insufficient_data")
    if signal.partition_count == 1:
        # A single physical partition cannot be *skewed*; an oversized single logical key inside it
        # is a Log Analytics follow-up (we cannot see logical sizes from the physical metric).
        return verdict(root_cause="single_partition")
    if signal.max_bytes < cfg.min_busiest_bytes:
        return verdict(root_cause="too_small")  # storage too small to matter
    if signal.balance_ratio >= cfg.balance_floor:
        # Partitions are evenly filled -> healthy distribution; they split as they grow. No action.
        return verdict(root_cause="uniform_storage")

    # Imbalanced + materially sized = storage skew. Severity by proximity to the physical ceiling.
    if signal.busiest_pct_of_limit >= cfg.high_pct_of_limit:
        severity = "high"
    elif signal.busiest_pct_of_limit >= cfg.medium_pct_of_limit:
        severity = "medium"
    else:
        severity = "low"

    busiest_gib = signal.max_bytes / 1024**3
    action = (
        f"Storage is concentrated on the busiest of {signal.partition_count} physical partitions "
        f"({busiest_gib:.1f} GiB, {signal.busiest_pct_of_limit:.0f}% of the 50 GiB physical limit) "
        f"while the coolest holds {signal.min_bytes / 1024**3:.1f} GiB. The partition key is "
        f"distributing data unevenly. Redesign the key for even distribution (higher cardinality, "
        f"hierarchical keys such as tenantId+id, or a hash prefix); re-keying an existing container "
        f"is migration-class. A physical partition cannot split when its data is one oversized "
        f"logical key, and a single logical key is hard-capped at 20 GiB — at which point writes to "
        f"it fail. Adding RU/s does not help storage skew."
    )
    return verdict(
        is_storage_skew=True, root_cause="storage_skew", severity=severity,
        recommended_action=action,
    )


def detect_storage_skew(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    offer: ThroughputOffer,
    window: TimeWindow,
    *,
    config: StorageSkewConfig | None = None,
    resource_created_at: datetime | None = None,
) -> StorageSkewVerdict:
    """End-to-end DX-015 for one container."""
    cfg = config or StorageSkewConfig()

    if resource_created_at is not None:
        age_insuff = evaluate_age(resource_created_at, window.end, AGE_FLOOR)
        if age_insuff is not None:
            return StorageSkewVerdict(
                is_storage_skew=False, partition_count=0, max_bytes=0.0, min_bytes=0.0,
                skew_ratio=0.0, busiest_pct_of_limit=0.0, root_cause="insufficient_data",
                severity="none", recommended_action="",
                methodology={"abstained": age_insuff.reason, "detail": age_insuff.detail},
            )

    scope = {"DatabaseName": database, "CollectionName": container}
    per_partition = metrics.get_metric_split(
        account_resource_id, "PhysicalPartitionSizeInfo", window,
        split_dimension="PhysicalPartitionId", dimension_filter=scope, aggregation="Maximum",
    )
    count, mx, mn, mean = storage_skew(per_partition)
    skew_ratio = (mx / mean) if mean > 0 else 0.0
    balance_ratio = (mn / mx) if mx > 0 else 1.0
    busiest_pct = 100.0 * mx / PHYSICAL_PARTITION_LIMIT_BYTES if mx > 0 else 0.0
    signal = StorageSkewSignal(
        partition_count=count, max_bytes=mx, min_bytes=mn, mean_bytes=mean,
        skew_ratio=skew_ratio, balance_ratio=balance_ratio, busiest_pct_of_limit=busiest_pct,
    )
    return classify(signal, cfg)

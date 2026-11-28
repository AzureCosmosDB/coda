"""DX-015 physical storage observations. Physical sizes alone cannot establish logical-key risk."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.detections.regional_skew import regional_verdict
from coda_core.providers.arm import ThroughputOffer
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricSeries, TimeWindow

# Verified Cosmos DB limits (Microsoft Learn, partitioning-overview): a physical partition holds up to
# 50 GiB of storage before the platform splits it; a single logical partition key is hard-capped at
# 20 GiB, after which writes to that key are blocked. These anchor the severity model and remediation.
PHYSICAL_PARTITION_LIMIT_BYTES = 50 * 1024**3
LOGICAL_PARTITION_LIMIT_BYTES = 20 * 1024**3

PRODUCTION_WINDOW_DAYS = 7


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

    return verdict(
        is_storage_skew=True, root_cause="storage_skew",
        recommended_action="Check the largest logical partitions; physical imbalance alone does not establish key size.",
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
    regions: tuple[str | None, ...] = (),
) -> StorageSkewVerdict:
    """End-to-end DX-015 for one container."""
    cfg = config or StorageSkewConfig()

    if resource_created_at is not None and resource_created_at > window.start:
        if resource_created_at >= window.end:
            return classify(StorageSkewSignal(0, 0, 0, 0, 0, 0, 0), cfg)
        window = TimeWindow(resource_created_at, window.end, window.granularity)
    histories = metrics.partition_histories(
        account_resource_id, "PhysicalPartitionSizeInfo", window, database=database,
        container=container, owner_rid=offer.owner_rid, regions=regions,
    )

    def classify_series(series):
        count, mx, mn, mean = storage_skew(series)
        return classify(StorageSkewSignal(
            count, mx, mn, mean, mx / mean if mean else 0, mn / mx if mx else 1,
            100 * mx / PHYSICAL_PARTITION_LIMIT_BYTES), cfg)

    return regional_verdict(
        histories, classify_series, skew_cause="storage_skew",
        observations=lambda v: {"observed_max_bytes": v.max_bytes, "observed_min_bytes": v.min_bytes})

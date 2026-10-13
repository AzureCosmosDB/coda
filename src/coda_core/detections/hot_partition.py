"""DX-006: Hot partition (partition-key skew).

A skewed partition key concentrates RU on a subset of physical partitions, so one partition
saturates (and may throttle) while the container as a whole looks under-utilized. The remedy is the
partition key, not more RU — distinguishing this from DX-005 (global under-provisioning) is the
whole point of the detection.

Detection signal: per-partition ``NormalizedRUConsumption`` (split by ``PhysicalPartitionId``). A hot
partition exists when the busiest partition is **saturated** (p99 >= ``saturation_pct``) **and** at
least one other partition has **headroom** (p99 < ``uniform_min_pct``). This is
partition-count-independent: it keys off "is some partition saturated while another is cool", not a
skew ratio that scales with partition count (a fixed ratio would never fire on a 2-partition
container). The skew ratio (max / mean) is reported as descriptive context only.

Severity scales with throttling (container-level 429 rate): **active throttling -> high**;
**saturated-but-not-throttling -> medium** (early warning — the hot partition is pinned and cannot
borrow the cool partitions' capacity, which becomes a real problem as load grows / the container
scales out to more partitions).

v1 detects **physical-partition RU skew** (Azure Monitor, no Log Analytics dependency). Identifying
the hot **logical key** (``CDBPartitionKeyRUConsumption``) and per-partition **storage** skew are
follow-ups. Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.detections.over_provisioning import utilization_stats
from coda_core.detections.under_provisioning import throttle_rate
from coda_core.providers.arm import ThroughputOffer
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricSeries, TimeWindow
from coda_core.sufficiency import evaluate_age

# Hot partition is present-tense: a short window with a 1-day age floor (like DX-005).
PRODUCTION_WINDOW_DAYS = 7
AGE_FLOOR = timedelta(days=1)


def production_window(now: datetime | None = None) -> TimeWindow:
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=PRODUCTION_WINDOW_DAYS), anchor, timedelta(hours=1))


@dataclass(frozen=True)
class PartitionSkewSignal:
    """Per-physical-partition utilization picture for one container."""

    partition_count: int
    max_p99: float            # busiest partition's p99 utilization
    min_p99: float            # coolest partition's p99 utilization
    mean_p99: float
    hot_partitions: int       # partitions with p99 >= saturation_pct
    cool_partitions: int      # partitions with p99 < uniform_min_pct (have headroom)
    skew_ratio: float         # max / mean — descriptive only, NOT the trigger
    throttle_rate_pct: float  # container-level 429 rate (drives severity)
    total_requests: float

    def as_dict(self) -> dict:
        return asdict(self)


def partition_skew(
    per_partition: dict[str, MetricSeries], *, saturation_pct: float, uniform_min_pct: float
) -> tuple[int, float, float, float, int, int, float]:
    """Return (count, max_p99, min_p99, mean_p99, hot, cool, skew_ratio) of per-partition p99s."""
    p99s = [utilization_stats(s).p99 for s in per_partition.values() if s.values()]
    if not p99s:
        return 0, 0.0, 0.0, 0.0, 0, 0, 0.0
    mx, mn, mean = max(p99s), min(p99s), sum(p99s) / len(p99s)
    hot = sum(1 for p in p99s if p >= saturation_pct)
    cool = sum(1 for p in p99s if p < uniform_min_pct)
    ratio = (mx / mean) if mean > 0 else 0.0
    return len(p99s), mx, mn, mean, hot, cool, ratio


@dataclass(frozen=True)
class HotPartitionConfig:
    """Tunable knobs. The 90% saturation / 70% headroom cutoffs are the same per-partition
    thresholds DX-005 uses (fleet-validated, ADR-0009)."""

    saturation_pct: float = 90.0     # a partition >= this is "hot"
    uniform_min_pct: float = 70.0    # a partition < this has "headroom"
    throttle_rate_pct: float = 1.0   # >= this container 429 rate = active throttling
    severity_high_throttle: float = 1.0  # throttling at/above this -> high severity


@dataclass(frozen=True)
class HotPartitionVerdict:
    is_hot_partition: bool
    partition_count: int
    max_p99: float
    min_p99: float
    skew_ratio: float
    throttling: bool
    # hot_partition | uniform_saturation | not_saturated | single_partition | insufficient_data
    root_cause: str
    severity: str  # high | medium | low | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def classify(
    signal: PartitionSkewSignal, config: HotPartitionConfig | None = None
) -> HotPartitionVerdict:
    """Map a per-partition skew signal to a hot-partition verdict."""
    cfg = config or HotPartitionConfig()
    throttling = signal.throttle_rate_pct >= cfg.throttle_rate_pct

    def verdict(**kw) -> HotPartitionVerdict:
        base = dict(
            is_hot_partition=False, partition_count=signal.partition_count,
            max_p99=round(signal.max_p99, 1), min_p99=round(signal.min_p99, 1),
            skew_ratio=round(signal.skew_ratio, 2), throttling=throttling,
            root_cause="not_saturated", severity="none", recommended_action="",
            methodology={"thresholds": {"saturation_pct": cfg.saturation_pct,
                                        "uniform_min_pct": cfg.uniform_min_pct},
                         "hot_partitions": signal.hot_partitions,
                         "cool_partitions": signal.cool_partitions,
                         "throttle_rate_pct": round(signal.throttle_rate_pct, 2)},
        )
        base.update(kw)
        return HotPartitionVerdict(**base)

    if signal.partition_count == 0:
        return verdict(root_cause="insufficient_data")
    if signal.partition_count == 1:
        return verdict(root_cause="single_partition")  # a single partition cannot be skewed
    if signal.max_p99 < cfg.saturation_pct:
        return verdict(root_cause="not_saturated")      # no partition is hot
    if signal.min_p99 >= cfg.uniform_min_pct:
        # Every partition is busy -> add capacity, not re-key. DX-005's (global) domain.
        return verdict(root_cause="uniform_saturation")

    # Saturated busiest partition + at least one cooler partition with headroom = hot partition.
    severity = "high" if throttling else "medium"
    action = (
        f"{signal.hot_partitions} of {signal.partition_count} physical partitions saturated "
        f"(busiest p99 {signal.max_p99:.0f}%) while others have headroom (coolest p99 "
        f"{signal.min_p99:.0f}%). Load is concentrated by the partition key. The fix is partition-key "
        f"redesign (higher cardinality, avoid hotspots, synthetic or hierarchical keys); re-keying an "
        f"existing container is migration-class. Per-partition/per-region autoscale only relieves the "
        f"cost of feeding the hot partition while the key is redesigned — it does not fix the "
        f"throttling (a single hot logical key is capped at one physical partition's ceiling)."
    )
    return verdict(
        is_hot_partition=True, root_cause="hot_partition", severity=severity,
        recommended_action=action,
    )


def detect_hot_partition(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    offer: ThroughputOffer,
    window: TimeWindow,
    *,
    config: HotPartitionConfig | None = None,
    resource_created_at: datetime | None = None,
) -> HotPartitionVerdict:
    """End-to-end DX-006 for one container."""
    cfg = config or HotPartitionConfig()

    if resource_created_at is not None:
        age_insuff = evaluate_age(resource_created_at, window.end, AGE_FLOOR)
        if age_insuff is not None:
            return HotPartitionVerdict(
                is_hot_partition=False, partition_count=0, max_p99=0.0, min_p99=0.0,
                skew_ratio=0.0, throttling=False, root_cause="insufficient_data", severity="none",
                recommended_action="",
                methodology={"abstained": age_insuff.reason, "detail": age_insuff.detail},
            )

    scope = {"DatabaseName": database} if container is None else \
        {"DatabaseName": database, "CollectionName": container}
    per_partition = metrics.get_metric_split(
        account_resource_id, "NormalizedRUConsumption", window,
        split_dimension="PhysicalPartitionId", dimension_filter=scope, aggregation="Maximum",
    )
    # TotalRequests is Count-native: aggregation="Count" gives the correct 429 rate; "Total"
    # mis-weights the sum per status code and returns a wrong throttle rate.
    total = metrics.get_metric(account_resource_id, "TotalRequests", window,
                               aggregation="Count", dimension_filter=scope)
    throttled = metrics.get_metric(account_resource_id, "TotalRequests", window, aggregation="Count",
                                   dimension_filter={**scope, "StatusCode": "429"})
    rate, t, _ = throttle_rate(total, throttled)
    count, mx, mn, mean, hot, cool, ratio = partition_skew(
        per_partition, saturation_pct=cfg.saturation_pct, uniform_min_pct=cfg.uniform_min_pct
    )
    signal = PartitionSkewSignal(
        partition_count=count, max_p99=mx, min_p99=mn, mean_p99=mean, hot_partitions=hot,
        cool_partitions=cool, skew_ratio=ratio, throttle_rate_pct=rate, total_requests=t,
    )
    return classify(signal, cfg)

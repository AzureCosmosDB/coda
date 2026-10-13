"""DX-017: Rapid storage growth (trending toward the partition limit).

Storage that grows quickly matters because of the hard ceilings a partition key can hit: a physical
partition caps at ~50 GiB and a single logical partition key at ~20 GiB, after which writes are
throttled or blocked. This detection fits a linear trend to each physical partition's storage and
projects **how soon the busiest-growing partition would reach the 50 GiB physical limit** at the
current rate. A short horizon is an early warning to add TTL / archival / a better partition key
*before* hitting the wall.

Signal: Azure Monitor ``PhysicalPartitionSizeInfo`` split by ``PhysicalPartitionId`` (no Log Analytics
dependency). Read-only / diagnose-only. Capacity/reliability framing (ADR-0012) — no cost figure.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricSeries, TimeWindow

PHYSICAL_PARTITION_LIMIT_BYTES = 50 * 1024**3
PRODUCTION_WINDOW_DAYS = 30
GRANULARITY = timedelta(hours=1)


def production_window(now: datetime | None = None) -> TimeWindow:
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=PRODUCTION_WINDOW_DAYS), anchor, GRANULARITY)


@dataclass(frozen=True)
class StorageGrowthConfig:
    min_current_bytes: float = 1.0 * 1024**3   # ignore partitions below 1 GiB (immaterial)
    min_rate_bytes_per_day: float = 0.1 * 1024**3  # ignore slower than 100 MiB/day (noise)
    horizon_high_days: float = 30.0    # projected to hit 50 GiB within this -> high
    horizon_medium_days: float = 90.0  # within this -> medium
    horizon_low_days: float = 180.0    # within this -> low (early warning)


@dataclass(frozen=True)
class StorageGrowthVerdict:
    is_rapid_growth: bool
    busiest_current_gib: float
    growth_rate_gib_per_day: float
    days_to_limit: float | None
    severity: str  # high | medium | low | none
    # rapid_growth | stable | too_small | insufficient_data
    root_cause: str
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _linear_rate_per_day(series: MetricSeries) -> tuple[float, float]:
    """Return (current_bytes, bytes_per_day) from a least-squares fit; (0,0) if too few points."""
    pts = [(p.timestamp, p.value) for p in series.points if p.value is not None]
    if len(pts) < 2:
        return (pts[-1][1] if pts else 0.0), 0.0
    t0 = pts[0][0]
    xs = [(t - t0).total_seconds() / 86400.0 for t, _ in pts]  # days since start
    ys = [v for _, v in pts]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    slope = (sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denom) if denom else 0.0
    return ys[-1], slope


def classify(
    busiest_current: float, rate_per_day: float, config: StorageGrowthConfig | None = None
) -> StorageGrowthVerdict:
    cfg = config or StorageGrowthConfig()
    gib = 1024**3
    over_limit = busiest_current >= PHYSICAL_PARTITION_LIMIT_BYTES
    days_to_limit = None
    if rate_per_day > 0 and not over_limit:
        days_to_limit = (PHYSICAL_PARTITION_LIMIT_BYTES - busiest_current) / rate_per_day

    def verdict(**kw) -> StorageGrowthVerdict:
        base = dict(is_rapid_growth=False, busiest_current_gib=round(busiest_current / gib, 2),
                    growth_rate_gib_per_day=round(rate_per_day / gib, 3),
                    days_to_limit=(round(days_to_limit, 1) if days_to_limit is not None else None),
                    severity="none", root_cause="stable", recommended_action="",
                    methodology={"physical_partition_limit_gib": PHYSICAL_PARTITION_LIMIT_BYTES // gib,
                                 "horizons_days": {"high": cfg.horizon_high_days,
                                                   "medium": cfg.horizon_medium_days,
                                                   "low": cfg.horizon_low_days}})
        base.update(kw)
        return StorageGrowthVerdict(**base)

    if busiest_current <= 0:
        return verdict(root_cause="insufficient_data")
    if busiest_current < cfg.min_current_bytes:
        return verdict(root_cause="too_small")
    if over_limit:
        # Already at/over the 50 GiB physical-partition limit — the most urgent case, NOT "stable".
        action = (
            f"The busiest physical partition is at {busiest_current / gib:.1f} GiB — at or over the "
            f"50 GiB physical-partition limit. It should have split; if it is dominated by one logical "
            f"partition key, that key is near the 20 GiB hard cap where writes begin to fail. Re-key to "
            f"a higher-cardinality partition key, add TTL on stale data, or archive cold data urgently."
        )
        return verdict(is_rapid_growth=True, severity="high", root_cause="at_or_over_limit",
                       recommended_action=action)
    if rate_per_day < cfg.min_rate_bytes_per_day or days_to_limit is None:
        return verdict(root_cause="stable")
    if days_to_limit > cfg.horizon_low_days:
        return verdict(root_cause="stable")

    if days_to_limit <= cfg.horizon_high_days:
        severity = "high"
    elif days_to_limit <= cfg.horizon_medium_days:
        severity = "medium"
    else:
        severity = "low"
    action = (
        f"The busiest physical partition is at {busiest_current / gib:.1f} GiB and growing "
        f"~{rate_per_day / gib:.2f} GiB/day — on track to reach the 50 GiB physical-partition limit "
        f"in ~{days_to_limit:.0f} days. Before that wall (a single logical key is also hard-capped at "
        f"20 GiB), add TTL on stale data, archive cold data, or move to a higher-cardinality "
        f"partition key so storage spreads across more partitions."
    )
    return verdict(is_rapid_growth=True, severity=severity, root_cause="rapid_growth",
                   recommended_action=action)


def detect_storage_growth(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    window: TimeWindow,
    *,
    config: StorageGrowthConfig | None = None,
) -> StorageGrowthVerdict:
    """End-to-end DX-017 for one container: project the fastest-growing partition to the limit."""
    per_partition = metrics.get_metric_split(
        account_resource_id, "PhysicalPartitionSizeInfo", window,
        split_dimension="PhysicalPartitionId",
        dimension_filter={"DatabaseName": database, "CollectionName": container},
        aggregation="Maximum",
    )
    # Pick the partition that would hit the limit soonest (highest current + rate).
    soonest: StorageGrowthVerdict | None = None
    for series in per_partition.values():
        current, rate = _linear_rate_per_day(series)
        v = classify(current, rate, config)
        if soonest is None:
            soonest = v
        elif v.days_to_limit is not None and (
            soonest.days_to_limit is None or v.days_to_limit < soonest.days_to_limit
        ):
            soonest = v
    return soonest or classify(0.0, 0.0, config)

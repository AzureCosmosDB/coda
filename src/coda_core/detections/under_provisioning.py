"""DX-005: Under-provisioning / throttling (reliability) — mode-aware (manual + autoscale).

Detects **genuine uniform under-provisioning**: a container sustaining 429 throttling while
**all** of its physical partitions are saturated (so it isn't a single hot partition — that's
DX-006). Severity is **reliability impact** (throttle rate), NOT cost.

Scope (ADR-0007 Option A): this detection is the "you simply need more capacity" case. Other
throttling causes are their own detections (DX-003 shared-pool starvation, DX-006 hot partition,
DX-010 ingestion storms); correlating them is a rollup-layer concern.

Signal sources (verified against live metric definitions):
  * throttle rate  = ``TotalRequests`` filtered by ``StatusCode='429'`` ÷ total ``TotalRequests``.
  * per-partition saturation = ``NormalizedRUConsumption`` split by ``PhysicalPartitionId``.
Reuses ``utilization_stats`` from DX-001 (shared signal). Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from coda_core.detections.over_provisioning import utilization_stats
from coda_core.providers.arm import ThroughputOffer
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricSeries, TimeWindow
from coda_core.sufficiency import evaluate_age

# DX-005 is present-tense: throttling sustained over the recent window, with a short age floor
# (unlike DX-001's 30d/7d). Tunable; to be validated against a throttling fixture.
PRODUCTION_WINDOW_DAYS = 7
AGE_FLOOR = timedelta(days=1)


def production_window(now: datetime | None = None) -> TimeWindow:
    from datetime import timezone
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=PRODUCTION_WINDOW_DAYS), anchor, timedelta(hours=1))


@dataclass(frozen=True)
class ThrottlingSignal:
    """The measured throttling + per-partition saturation picture for one container."""

    total_requests: float
    throttled_requests: float
    throttle_rate_pct: float
    partition_count: int
    max_partition_p99: float  # highest partition utilization (is anything saturated?)
    min_partition_p99: float  # lowest partition utilization (are they ALL saturated? = uniform)

    def as_dict(self) -> dict:
        return asdict(self)


def throttle_rate(total: MetricSeries, throttled: MetricSeries) -> tuple[float, float, float]:
    """Return (rate_pct, total_requests, throttled_requests)."""
    t = sum(total.values())
    r = sum(throttled.values())
    return (100.0 * r / t if t else 0.0), t, r


def partition_saturation(per_partition: dict[str, MetricSeries]) -> tuple[int, float, float]:
    """Return (partition_count, max_p99, min_p99) of per-partition utilization."""
    p99s = [utilization_stats(s).p99 for s in per_partition.values() if s.values()]
    if not p99s:
        return 0, 0.0, 0.0
    return len(p99s), max(p99s), min(p99s)


@dataclass(frozen=True)
class UnderProvisioningConfig:
    """Tunable knobs (methodology + thresholds: ADR-0009). The 1% throttle floor catches ~92% of
    real throttling; the 5%/20% severity cutoffs sit at ~p25/p50 of the fleet per-partition throttle
    distribution (docs/evidence/threshold-grounding.md)."""

    throttle_rate_pct: float = 1.0   # >=1% sustained 429s = throttling
    saturation_pct: float = 90.0     # partition p99 >= this = at capacity
    uniform_min_pct: float = 70.0    # MIN partition p99 >= this = uniform (all hot), not skewed
    min_total_requests: float = 1000.0  # below this, the rate is too noisy to judge
    severity_high_pct: float = 20.0
    severity_med_pct: float = 5.0


@dataclass(frozen=True)
class UnderProvisioningVerdict:
    is_under_provisioned: bool
    throttle_rate_pct: float
    at_capacity: bool
    uniform: bool
    root_cause: str       # global_under_provisioning | skew_suspected | not_throttling
    mode: str             # manual | autoscale
    recommended_action: str
    severity: str         # high | medium | low | none  (reliability)
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _severity(rate: float, cfg: UnderProvisioningConfig) -> str:
    if rate >= cfg.severity_high_pct:
        return "high"
    if rate >= cfg.severity_med_pct:
        return "medium"
    return "low"


def classify(
    signal: ThrottlingSignal, offer: ThroughputOffer, config: UnderProvisioningConfig | None = None
) -> UnderProvisioningVerdict:
    """Map a throttling signal + throughput offer to a mode-aware under-provisioning verdict."""
    cfg = config or UnderProvisioningConfig()
    throttling = signal.throttle_rate_pct >= cfg.throttle_rate_pct
    at_capacity = signal.max_partition_p99 >= cfg.saturation_pct
    uniform = signal.min_partition_p99 >= cfg.uniform_min_pct

    def verdict(**kw) -> UnderProvisioningVerdict:
        base = dict(
            is_under_provisioned=False, throttle_rate_pct=round(signal.throttle_rate_pct, 2),
            at_capacity=at_capacity, uniform=uniform, root_cause="not_throttling",
            mode=offer.mode, recommended_action="", severity="none",
            methodology={"thresholds": {"throttle_pct": cfg.throttle_rate_pct,
                                        "saturation_pct": cfg.saturation_pct,
                                        "uniform_min_pct": cfg.uniform_min_pct},
                         "partition_count": signal.partition_count},
        )
        base.update(kw)
        return UnderProvisioningVerdict(**base)

    if not (throttling and at_capacity):
        return verdict()

    if not uniform:
        # Saturated + throttling but NOT all partitions hot -> likely a hot partition (DX-006).
        return verdict(
            root_cause="skew_suspected", severity=_severity(signal.throttle_rate_pct, cfg),
            recommended_action="Throttling appears driven by partition skew, not global "
                               "under-provisioning -> investigate hot partition (DX-006).",
        )

    if offer.mode == "autoscale":
        action = (f"Raise the autoscale max above {offer.provisioned_ru:.0f} RU/s "
                  f"(it is pinned at the ceiling).")
    else:
        action = (f"Raise provisioned throughput above {offer.provisioned_ru:.0f} RU/s, "
                  f"or convert to autoscale.")
    return verdict(
        is_under_provisioned=True, root_cause="global_under_provisioning",
        recommended_action=action, severity=_severity(signal.throttle_rate_pct, cfg),
    )


def detect_under_provisioning(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    offer: ThroughputOffer,
    window: TimeWindow,
    *,
    config: UnderProvisioningConfig | None = None,
    resource_created_at: datetime | None = None,
) -> UnderProvisioningVerdict:
    """End-to-end DX-005 for one container (manual or autoscale)."""
    cfg = config or UnderProvisioningConfig()

    if resource_created_at is not None:
        age_insuff = evaluate_age(resource_created_at, window.end, AGE_FLOOR)
        if age_insuff is not None:
            return _abstain(offer, reason=age_insuff.reason, detail=age_insuff.detail)

    scope = {"DatabaseName": database} if container is None else \
        {"DatabaseName": database, "CollectionName": container}
    # TotalRequests is Count-native: aggregation="Count" gives the correct 429 rate; "Total"
    # mis-weights the sum per status code and returns a wrong throttle rate.
    total = metrics.get_metric(account_resource_id, "TotalRequests", window,
                               aggregation="Count", dimension_filter=scope)
    throttled = metrics.get_metric(account_resource_id, "TotalRequests", window, aggregation="Count",
                                   dimension_filter={**scope, "StatusCode": "429"})
    per_partition = metrics.get_metric_split(
        account_resource_id, "NormalizedRUConsumption", window,
        split_dimension="PhysicalPartitionId", dimension_filter=scope, aggregation="Maximum",
    )

    rate, t, r = throttle_rate(total, throttled)
    if t < cfg.min_total_requests:
        return _abstain(offer, reason="too_few_requests", detail=f"{t:.0f} requests in window")
    count, max_p99, min_p99 = partition_saturation(per_partition)
    signal = ThrottlingSignal(
        total_requests=t, throttled_requests=r, throttle_rate_pct=rate,
        partition_count=count, max_partition_p99=max_p99, min_partition_p99=min_p99,
    )
    return classify(signal, offer, cfg)


def _abstain(offer: ThroughputOffer, *, reason: str, detail: str) -> UnderProvisioningVerdict:
    return UnderProvisioningVerdict(
        is_under_provisioned=False, throttle_rate_pct=0.0, at_capacity=False, uniform=False,
        root_cause="insufficient_data", mode=offer.mode, recommended_action="", severity="none",
        methodology={"abstained": reason, "detail": detail},
    )

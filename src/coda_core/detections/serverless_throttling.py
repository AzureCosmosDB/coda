"""DX-018: Serverless throttling (reliability).

A serverless container has **no provisioned-throughput knob**. Its maximum throughput is
``number_of_physical_partitions × 5,000 RU/s`` (verified against the Azure Cosmos DB "Serverless
performance" doc: a single-partition container is capped at 5,000 RU/s, and capacity scales linearly
as the data grows and splits into more partitions). The ceiling is **instantaneous (per-second)**, so
short bursts above it are throttled (429) even when a minute-averaged RU/s sits well below the cap
(live-validated: 5.7% 429s at a ~2,400 RU/s minute average, because sub-second bursts crossed 5,000).

Because serverless offers **no way to raise throughput**, sustained throttling means the workload has
outgrown the serverless model. The remediation is to **migrate to provisioned throughput** (manual or
autoscale), which provides higher, predictable, scalable capacity. This is fundamentally different
from DX-005 (provisioned under-provisioning, whose fix is "raise RU/s") — and the two never overlap
because **serverless containers produce no throughput offer**, so DX-005 never sees them. DX-018 is
gated on the account's ``EnableServerless`` capability and runs on a dedicated serverless-container
pass.

Telemetry limit (verified, honest): for serverless containers, ``NormalizedRUConsumption`` is **not
emitted**, so CODA cannot measure per-partition RU and cannot attribute throttling to a single hot
partition vs broad saturation. The signal is therefore the container-level 429 rate, and the
recommendation is provisioned throughput (the reliable fix) — noting that, for a multi-partition
container, better partition-key distribution *could* use idle partitions' 5,000 RU/s budgets, which
CODA cannot confirm from serverless telemetry. Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricSeries, TimeWindow

# Verified serverless ceiling (Azure Cosmos DB "Serverless performance"): 5,000 RU/s per physical
# partition; total container capacity = partitions × 5,000. Used in the finding text, not as a
# threshold (the metric reads 429 rate, not absolute RU/s — see module docstring).
SERVERLESS_RU_PER_PARTITION = 5000

PRODUCTION_WINDOW_DAYS = 7


def production_window(now: datetime | None = None) -> TimeWindow:
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=PRODUCTION_WINDOW_DAYS), anchor, timedelta(hours=1))


@dataclass(frozen=True)
class ServerlessThrottleConfig:
    """Tunable knobs. Mirrors DX-005's reliability bands: the 1% floor catches real throttling; the
    5%/20% cutoffs are the medium/high reliability-impact boundaries."""

    throttle_rate_pct: float = 1.0      # >= 1% sustained 429s = throttling
    min_total_requests: float = 1000.0  # below this, the rate is too noisy to judge
    severity_high_pct: float = 20.0
    severity_med_pct: float = 5.0


@dataclass(frozen=True)
class ServerlessThrottleVerdict:
    is_throttling: bool
    throttle_rate_pct: float
    total_requests: float
    throttled_requests: float
    root_cause: str       # serverless_throttling | not_throttling | insufficient_data
    severity: str         # high | medium | low | none (reliability)
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def throttle_rate(total: MetricSeries, throttled: MetricSeries) -> tuple[float, float, float]:
    """Return (rate_pct, total_requests, throttled_requests). Shared shape with DX-005."""
    t = sum(total.values())
    r = sum(throttled.values())
    return (100.0 * r / t if t else 0.0), t, r


def _severity(rate: float, cfg: ServerlessThrottleConfig) -> str:
    if rate >= cfg.severity_high_pct:
        return "high"
    if rate >= cfg.severity_med_pct:
        return "medium"
    return "low"


_ACTION = (
    "This serverless container is being throttled (429s). Serverless capacity is capped at "
    f"{SERVERLESS_RU_PER_PARTITION:,} RU/s per physical partition (the ceiling is per-second, so "
    "bursts are throttled even when the minute-averaged RU/s looks lower) and serverless has no knob "
    "to raise throughput. Evaluate migrating this container to provisioned throughput (autoscale or "
    "manual) for higher, predictable, scalable capacity. Note: serverless total capacity scales as "
    "partitions × 5,000 RU/s, so on a multi-partition container better partition-key distribution may "
    "help — but per-partition RU is not exposed for serverless, so provisioned throughput is the "
    "reliable fix."
)


def classify(
    signal_rate: float, total_requests: float, throttled_requests: float,
    config: ServerlessThrottleConfig | None = None,
) -> ServerlessThrottleVerdict:
    """Map a serverless container's 429 rate to a throttling verdict (pure)."""
    cfg = config or ServerlessThrottleConfig()

    def verdict(**kw) -> ServerlessThrottleVerdict:
        base = dict(
            is_throttling=False, throttle_rate_pct=round(signal_rate, 2),
            total_requests=total_requests, throttled_requests=throttled_requests,
            root_cause="not_throttling", severity="none", recommended_action="",
            methodology={"thresholds": {"throttle_pct": cfg.throttle_rate_pct,
                                        "severity_med_pct": cfg.severity_med_pct,
                                        "severity_high_pct": cfg.severity_high_pct},
                         "serverless_ru_per_partition": SERVERLESS_RU_PER_PARTITION,
                         "per_partition_ru_available": False},
        )
        base.update(kw)
        return ServerlessThrottleVerdict(**base)

    if total_requests < cfg.min_total_requests:
        return verdict(root_cause="insufficient_data", methodology={
            "abstained": "too_few_requests", "detail": f"{total_requests:.0f} requests in window"})
    if signal_rate < cfg.throttle_rate_pct:
        return verdict()
    return verdict(
        is_throttling=True, root_cause="serverless_throttling",
        severity=_severity(signal_rate, cfg), recommended_action=_ACTION,
    )


def detect_serverless_throttling(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    window: TimeWindow,
    *,
    config: ServerlessThrottleConfig | None = None,
) -> ServerlessThrottleVerdict:
    """End-to-end DX-018 for one serverless container."""
    cfg = config or ServerlessThrottleConfig()
    scope = {"DatabaseName": database, "CollectionName": container}
    # TotalRequests is Count-native: aggregation="Count" gives the correct 429 rate; "Total"
    # mis-weights the sum per status code and returns a wrong throttle rate.
    total = metrics.get_metric(account_resource_id, "TotalRequests", window,
                               aggregation="Count", dimension_filter=scope)
    throttled = metrics.get_metric(account_resource_id, "TotalRequests", window, aggregation="Count",
                                   dimension_filter={**scope, "StatusCode": "429"})
    rate, t, r = throttle_rate(total, throttled)
    return classify(rate, t, r, cfg)

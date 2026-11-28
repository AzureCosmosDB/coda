"""DX-004: Idle container (decommission / lifecycle review).

A provisioned offer with no measured consumption for 30 consecutive days. The inverse of
DX-001: DX-001 right-sizes a *used-but-over-provisioned* container (recover the over-provisioned
delta); DX-004 flags an *unused* container whose **entire** reservation is recoverable by
decommission, TTL, or archival. DX-004 surfaces recoverable capacity DX-001 cannot: a container
already at the 400 RU/s floor has no right-size savings yet is fully recoverable if it is truly idle.

Signal (distinct from DX-001's utilization percentile): **peak RU consumed per 5-minute bucket** —
``max(TotalRequestUnits, Total)`` over the window. Any positive RU, however small, rules out idle:
a container silent for 29 days that runs a real monthly batch on day 30 shows a large peak in one
bucket and is correctly **not** flagged (an average would hide the spike). The signal is
``max(TotalRequestUnits @ Total, PT5M)`` in Azure Monitor; ``NormalizedRUConsumption`` ≈ 0
corroborates it.

Note: we deliberately do **not** gate on ``TotalRequests`` — on live Cosmos accounts that metric is
frequently unpopulated (returns no data at all), which would make a request-count gate read every
container as idle. RU consumed (``TotalRequestUnits``) is the decision signal.

Only a complete grid of measured zeros on this resource can justify a retirement review.
Missing or null buckets and pre-creation padding cannot establish inactivity (ADR-0085).

Mode-aware recoverable cost: manual idle bills the **full** provisioned RU/s (all recoverable);
autoscale idle scales to ~10% of its max (that idle floor is what's recoverable). Severity reuses
the shared cost-materiality model (``framework/materiality``). Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from math import isfinite
from azure.core.exceptions import AzureError

from coda_core.framework.materiality import MaterialityConfig
from coda_core.framework.materiality import severity as materiality_severity
from coda_core.providers.arm import ThroughputOffer
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow, covers_bucket_grid
from coda_core.providers.monitor_retry import MonitorUnavailable
from coda_core.providers.shared_offer import IncompletePool, PoolMembers, owner_scope, traffic_metric

# Retirement advice needs a complete measured month on the same throughput offer (ADR-0085).
PRODUCTION_WINDOW_DAYS = 30
GRANULARITY = timedelta(minutes=5)
AGE_FLOOR = timedelta(days=PRODUCTION_WINDOW_DAYS)
REQUIRED_BUCKETS = AGE_FLOOR // GRANULARITY
# When idle, autoscale scales down to ~10% of its configured max — that floor is what is billed
# (and therefore recoverable on decommission). Manual recovers the full provisioned RU/s.
AUTOSCALE_IDLE_FRACTION = 0.10


def _closed_end(end: datetime) -> datetime:
    """Find the exclusive UTC end of the last fully elapsed five-minute bucket."""
    end = end.astimezone(timezone.utc)
    return end.replace(minute=end.minute-end.minute % 5, second=0, microsecond=0)


def production_window(now: datetime | None = None) -> TimeWindow:
    """Request 30 closed days plus any current partial bucket, whose usage can veto retirement."""
    end = now or datetime.now(timezone.utc)
    return TimeWindow(_closed_end(end) - AGE_FLOOR, end, GRANULARITY)


@dataclass(frozen=True)
class IdleSignal:
    """What we measured for one container over the window."""

    peak_ru: float             # max RU consumed in any 5-min bucket (TotalRequestUnits Total) — the gate
    max_utilization_pct: float | None  # corroborating only; absence is not measured zero
    complete_zero_window: bool = False  # Never infer a month of zeros from a scalar peak alone.

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class IdleConfig:
    """Severity is configurable; retirement's exact-zero requirement is not."""

    max_idle_peak_ru: float = field(default=0.0, init=False)
    materiality: MaterialityConfig = field(default_factory=MaterialityConfig)


@dataclass(frozen=True)
class IdleVerdict:
    is_idle: bool
    peak_ru: float | None
    recoverable_ru: float
    severity: str                       # high | medium | low | none (capacity materiality)
    materiality_pct: float | None       # recoverable RU/s as % of scope provisioned RU/s
    mode: str                           # manual | autoscale
    root_cause: str                     # idle | active | insufficient_data
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _recoverable_ru(offer: ThroughputOffer) -> float:
    """RU/s recoverable if the (idle) container is decommissioned, by billing mode."""
    if offer.mode == "autoscale":
        # Idle autoscale bills its floor (~10% of max); that is what decommission recovers.
        return AUTOSCALE_IDLE_FRACTION * offer.provisioned_ru
    return offer.provisioned_ru  # manual bills the full configured RU/s


def classify(
    signal: IdleSignal,
    offer: ThroughputOffer,
    *,
    config: IdleConfig | None = None,
    scope_provisioned_ru: float | None = None,
) -> IdleVerdict:
    """Map an idle signal + throughput offer to an idle verdict + recoverable RU/s + severity.

    Reports **capacity (RU/s), not cost** (ADR-0012): recoverable RU/s is manual full provisioned
    or the autoscale idle floor; severity is capacity-relative materiality.
    """
    cfg = config or IdleConfig()

    def verdict(**kw) -> IdleVerdict:
        base = dict(
            is_idle=False, peak_ru=signal.peak_ru, recoverable_ru=0.0,
            severity="none", materiality_pct=None,
            mode=offer.mode, root_cause="active", recommended_action="",
            methodology={"max_idle_peak_ru": cfg.max_idle_peak_ru,
                         "peak_ru": signal.peak_ru,
                         "max_utilization_pct": (round(signal.max_utilization_pct, 2)
                                                 if signal.max_utilization_pct is not None else None)},
        )
        base.update(kw)
        return IdleVerdict(**base)

    if not isfinite(signal.peak_ru) or signal.peak_ru < 0:
        return _insufficient(offer, "invalid_consumption", "Invalid consumed-RU measurement.")
    if signal.peak_ru > 0:
        return verdict()
    if not signal.complete_zero_window:
        return _insufficient(offer, "incomplete_idle_window", "30 consecutive measured days at zero RU required.", 0)

    recoverable = _recoverable_ru(offer)
    sev, mat_pct = materiality_severity(recoverable, scope_provisioned_ru, cfg.materiality,
                                        applicable=True)
    if offer.mode == "autoscale":
        action = ("Zero RU consumed for 30 consecutive days. Confirm ownership and scheduled workloads; review for "
                  f"decommission/TTL/archival; recovers the autoscale idle floor "
                  f"(~{recoverable:.0f} RU/s of max {offer.provisioned_ru:.0f}).")
    else:
        action = ("Zero RU consumed for 30 consecutive days. Confirm ownership and scheduled workloads; review for "
                  f"decommission/TTL/archival; recovers all {recoverable:.0f} RU/s.")
    return verdict(
        is_idle=True, root_cause="idle", recoverable_ru=recoverable, severity=sev,
        materiality_pct=(round(mat_pct, 2) if mat_pct is not None else None),
        recommended_action=action,
    )


def _insufficient(offer, reason, detail, peak=None, **evidence) -> IdleVerdict:
    """Keep measured activity separate from permission to count recoverable capacity."""
    return IdleVerdict(False, peak, 0.0, "none", None, offer.mode, "insufficient_data", "",
                       {"abstained": reason, "detail": detail, "peak_ru": peak, **evidence})


def detect_idle(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    offer: ThroughputOffer,
    window: TimeWindow,
    *,
    config: IdleConfig | None = None,
    scope_provisioned_ru: float | None = None,
    resource_created_at: datetime | None = None,
    resource_existed_by: datetime | None = None,
    pool_members: PoolMembers | None = None,
) -> IdleVerdict:
    """Observe usage on every applicable offer; only a verified month of zeros unlocks retirement."""
    cfg = config or IdleConfig()

    closed_end = _closed_end(window.end)
    since = closed_end - AGE_FLOOR
    start = max(window.start, since)
    if resource_created_at is not None:
        start = max(start, resource_created_at)
    if start >= window.end:
        return _insufficient(offer, "too_new", "No observation window after resource creation.")
    window = TimeWindow(start, window.end, window.granularity)

    # Peak RU consumed in any single bucket (spike-aware idle gate). TotalRequestUnits is populated
    # on live accounts where TotalRequests is not — see the module docstring.
    try:
        ru = traffic_metric(metrics, account_resource_id, "TotalRequestUnits", window,
                            database=database, container=container, pool=pool_members, aggregation="Total")
    except IncompletePool as exc:
        return _insufficient(offer, exc.reason, str(exc))
    samples = [p for p in ru.points if start <= p.timestamp < window.end and p.value is not None]
    if not samples:
        return _insufficient(offer, "no_data", "No measured consumption in the observation window.")
    if any(not isfinite(p.value) or p.value < 0 for p in samples):
        return _insufficient(offer, "invalid_consumption", "Invalid consumed-RU measurement.")
    peak = max(p.value for p in samples)
    stamps = sorted(p.timestamp for p in samples if p.timestamp < closed_end)
    distinct = len(set(stamps))
    evidence = {"required_buckets": REQUIRED_BUCKETS, "observed_closed_buckets": distinct,
                "required_start": since.isoformat(), "closed_end": closed_end.isoformat()}
    if peak == 0:
        existed = resource_created_at or resource_existed_by
        detail = (f"Observed zero RU in {distinct:,} closed buckets; retirement requires "
                  f"{REQUIRED_BUCKETS:,} consecutive five-minute zeros (30 days).")
        if existed is None or existed > since:
            reason = "too_new" if resource_created_at is not None else "resource_age_unknown"
            why = "Resource did not yet exist at the start." if resource_created_at else "Minimum age unverified."
            return _insufficient(offer, reason, f"{detail} {why}", 0, **evidence)
        if (window.granularity != GRANULARITY or start > since or len(stamps) != REQUIRED_BUCKETS
                or not covers_bucket_grid(stamps, TimeWindow(since, closed_end, GRANULARITY))):
            return _insufficient(offer, "incomplete_idle_window", f"{detail} Coverage is incomplete.", 0, **evidence)
    utilization_issue = None
    try:
        utilization = metrics.get_metric(account_resource_id, "NormalizedRUConsumption", window,
            aggregation="Maximum", dimension_filter=owner_scope(database, container, offer.owner_rid))
    except (AzureError, IncompletePool) as exc:
        utilization = None
        detail = str(exc) if isinstance(exc, MonitorUnavailable) else type(exc).__name__
        utilization_issue = f"Optional utilization unavailable: {detail}"
    util_values = utilization.values() if utilization is not None else []
    signal = IdleSignal(
        peak_ru=peak, complete_zero_window=peak == 0,
        max_utilization_pct=max(util_values) if util_values else None,
    )
    result = classify(signal, offer, config=cfg, scope_provisioned_ru=scope_provisioned_ru)
    result.methodology.update(evidence)
    if utilization_issue:
        result.methodology["utilization_issue"] = utilization_issue
    return result

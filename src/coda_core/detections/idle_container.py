"""DX-004: Idle container (decommission / lifecycle review).

A container that is provisioned but serves **~no traffic** — pure 24/7 waste. The inverse of
DX-001: DX-001 right-sizes a *used-but-over-provisioned* container (recover the over-provisioned
delta); DX-004 flags an *unused* container whose **entire** reservation is recoverable by
decommission, TTL, or archival. DX-004 surfaces recoverable capacity DX-001 cannot: a container
already at the 400 RU/s floor has no right-size savings yet is fully recoverable if it is truly idle.

Signal (distinct from DX-001's utilization percentile): **peak RU consumed per 5-minute bucket** —
``max(TotalRequestUnits, Total)`` over the window. A container that never spends more than a tiny
system-floor of RU in *any* 5-minute bucket did no real work ⇒ idle. This is explicitly spike-aware:
a container silent for 29 days that runs a real monthly batch on day 30 shows a large peak in one
bucket and is correctly **not** flagged (an average would hide the spike). The signal is
``max(TotalRequestUnits @ Total, PT5M)`` in Azure Monitor; ``NormalizedRUConsumption`` ≈ 0
corroborates it.

Note: we deliberately do **not** gate on ``TotalRequests`` — on live Cosmos accounts that metric is
frequently unpopulated (returns no data at all), which would make a request-count gate read every
container as idle. RU consumed (``TotalRequestUnits``) is the decision signal.

Azure Monitor can return *zero-valued* observations for idle windows. Measured "peak ≈ 0" is
positive idle evidence; a successful read with no usable observations is **insufficient data**,
not a measured zero (ADR-0076). The existing age guard remains; non-zero points are not required.

Mode-aware recoverable cost: manual idle bills the **full** provisioned RU/s (all recoverable);
autoscale idle scales to ~10% of its max (that idle floor is what's recoverable). Severity reuses
the shared cost-materiality model (``framework/materiality``). Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from azure.core.exceptions import AzureError

from coda_core.framework.materiality import MaterialityConfig
from coda_core.framework.materiality import severity as materiality_severity
from coda_core.providers.arm import ThroughputOffer
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow
from coda_core.providers.monitor_retry import MonitorUnavailable
from coda_core.providers.shared_offer import IncompletePool, PoolMembers, owner_scope, traffic_metric
from coda_core.sufficiency import DataRequirement, evaluate_age, evaluate_series

# Idle is a destructive-remediation detection, so it needs a LONG, high-confidence window to avoid
# flagging periodic (e.g. monthly-batch) containers, plus an age floor (ADR-0008). PT5M granularity
# matches the sister tool's MaxConsumedRUPer5M and is spike-aware at fine resolution.
PRODUCTION_WINDOW_DAYS = 30
GRANULARITY = timedelta(minutes=5)
AGE_FLOOR = timedelta(days=7)
DATA_REQUIREMENT = DataRequirement(window_floor=timedelta(0), min_points=1)
# When idle, autoscale scales down to ~10% of its configured max — that floor is what is billed
# (and therefore recoverable on decommission). Manual recovers the full provisioned RU/s.
AUTOSCALE_IDLE_FRACTION = 0.10


def production_window(now: datetime | None = None) -> TimeWindow:
    """The production DX-004 window: 30 days ending now, five-minute buckets."""
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=PRODUCTION_WINDOW_DAYS), anchor, GRANULARITY)


@dataclass(frozen=True)
class IdleSignal:
    """What we measured for one container over the window."""

    peak_ru: float             # max RU consumed in any 5-min bucket (TotalRequestUnits Total) — the gate
    max_utilization_pct: float | None  # corroborating only; absence is not measured zero

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class IdleConfig:
    """Tunable knobs. ``max_idle_peak_ru`` is a deliberately conservative near-zero floor on the
    peak RU consumed in any single 5-min bucket. Live fleet/fixture grounding: truly-idle containers
    peak at ~4 RU per 5-min (system floor), while the least-active *real* workload peaks at ~1,764 RU
    — a ~440× gap, so the default 50 RU sits comfortably above the idle floor and far below any real
    workload. Right for a destructive (decommission) remediation."""

    max_idle_peak_ru: float = 50.0  # peak RU in any 5-min bucket at/below this = idle
    materiality: MaterialityConfig = field(default_factory=MaterialityConfig)


@dataclass(frozen=True)
class IdleVerdict:
    is_idle: bool
    peak_ru: float
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
                         "peak_ru": round(signal.peak_ru, 1),
                         "max_utilization_pct": (round(signal.max_utilization_pct, 2)
                                                 if signal.max_utilization_pct is not None else None)},
        )
        base.update(kw)
        return IdleVerdict(**base)

    if signal.peak_ru > cfg.max_idle_peak_ru:
        return verdict()  # active — consumed real RU in some bucket, not idle (DX-001 right-sizes)

    recoverable = _recoverable_ru(offer)
    sev, mat_pct = materiality_severity(recoverable, scope_provisioned_ru, cfg.materiality,
                                        applicable=True)
    if offer.mode == "autoscale":
        action = (f"Container is idle (peak ≈{signal.peak_ru:.0f} RU/5min in window). Review for "
                  f"decommission/TTL/archival; recovers the autoscale idle floor "
                  f"(~{recoverable:.0f} RU/s of max {offer.provisioned_ru:.0f}).")
    else:
        action = (f"Container is idle (peak ≈{signal.peak_ru:.0f} RU/5min in window). Review for "
                  f"decommission/TTL/archival; recovers all {recoverable:.0f} RU/s.")
    return verdict(
        is_idle=True, root_cause="idle", recoverable_ru=recoverable, severity=sev,
        materiality_pct=(round(mat_pct, 2) if mat_pct is not None else None),
        recommended_action=action,
    )


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
    pool_members: PoolMembers | None = None,
) -> IdleVerdict:
    """End-to-end DX-004 for one container (manual or autoscale).

    Empty/all-null consumption abstains; measured zeros can establish idleness. The age guard
    also abstains for a known young resource that has not accrued representative history.
    """
    cfg = config or IdleConfig()

    if resource_created_at is not None:
        age_insuff = evaluate_age(resource_created_at, window.end, AGE_FLOOR)
        if age_insuff is not None:
            return IdleVerdict(
                is_idle=False, peak_ru=0.0, recoverable_ru=0.0,
                severity="none", materiality_pct=None,
                mode=offer.mode, root_cause="insufficient_data", recommended_action="",
                methodology={"abstained": age_insuff.reason, "detail": age_insuff.detail},
            )

    # Peak RU consumed in any single bucket (spike-aware idle gate). TotalRequestUnits is populated
    # on live accounts where TotalRequests is not — see the module docstring.
    try:
        ru = traffic_metric(metrics, account_resource_id, "TotalRequestUnits", window,
                            database=database, container=container, pool=pool_members, aggregation="Total")
    except IncompletePool as exc:
        return IdleVerdict(False, 0.0, 0.0, "none", None, offer.mode, "insufficient_data", "",
                           {"abstained": exc.reason, "detail": str(exc)})
    insuff = evaluate_series(ru, DATA_REQUIREMENT)
    if insuff is not None:
        return IdleVerdict(
            is_idle=False, peak_ru=0.0, recoverable_ru=0.0,
            severity="none", materiality_pct=None,
            mode=offer.mode, root_cause="insufficient_data", recommended_action="",
            methodology={"abstained": insuff.reason, "detail": insuff.detail},
        )
    utilization_issue = None
    try:
        utilization = metrics.get_metric(account_resource_id, "NormalizedRUConsumption", window,
            aggregation="Maximum", dimension_filter=owner_scope(database, container, offer.owner_rid))
    except (AzureError, IncompletePool) as exc:
        utilization = None
        detail = str(exc) if isinstance(exc, MonitorUnavailable) else type(exc).__name__
        utilization_issue = f"Optional utilization unavailable: {detail}"
    ru_values = ru.values()
    util_values = utilization.values() if utilization is not None else []
    signal = IdleSignal(
        peak_ru=max(ru_values),
        max_utilization_pct=max(util_values) if util_values else None,
    )
    result = classify(signal, offer, config=cfg, scope_provisioned_ru=scope_provisioned_ru)
    if utilization_issue:
        result.methodology["utilization_issue"] = utilization_issue
    return result

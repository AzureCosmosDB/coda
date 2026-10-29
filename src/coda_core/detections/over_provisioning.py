"""DX-001 manual provisioned over-provisioning — utilization signal + right-size classifier.

Scope: **manual (standard) provisioned throughput only.** Autoscale and serverless have different
economics and remediations (see docs/detections/throughput-right-sizing-family.md). The
``utilization_stats`` signal is shared with DX-004 (idle) and DX-005 (under-provisioning).

Signal: ``NormalizedRUConsumption`` (the % of provisioned capacity consumed at the busiest
partition, per minute). This module computes the utilization distribution over the window
(average, p50, p95, p99, max) and classifies it: the **P99** band decides whether the container is
over-provisioned; the classifier recommends a right-size target and a capacity-relative materiality
severity. Methodology and thresholds: ADR-0011. Quantities are **capacity (RU/s), not cost**
(ADR-0012).
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.framework.materiality import MaterialityConfig
from coda_core.framework.materiality import severity as materiality_severity
from coda_core.providers.base import DataProvider, MetricSeries, TimeWindow
from coda_core.sufficiency import DataRequirement, evaluate_age, evaluate_series

# Autoscale's configurable maximum baseline, not its scaled/billed idle floor (ADR-0016).
AUTOSCALE_MIN_MAX_RU = 1000


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Linear-interpolation percentile (``pct`` in 0..100). Pure-Python, no numpy.

    Assumes ``sorted_values`` is non-empty and already sorted ascending.
    """
    if not sorted_values:
        raise ValueError("percentile of empty sequence")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    frac = rank - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * frac


@dataclass(frozen=True)
class UtilizationStats:
    """Distribution of per-minute utilization (% of provisioned) over a window.

    All values are percentages (0..100). ``sample_count`` is the number of non-null
    metric points the stats were computed from.
    """

    sample_count: int
    avg: float
    p50: float
    p95: float
    p99: float
    max: float
    min: float

    def as_dict(self) -> dict:
        return asdict(self)


def utilization_stats(series: MetricSeries) -> UtilizationStats:
    """Compute the utilization distribution from a NormalizedRUConsumption series.

    Args:
        series: A ``MetricSeries`` of NormalizedRUConsumption (per-minute values).

    Returns:
        A ``UtilizationStats`` summarizing the distribution.

    Raises:
        ValueError: If the series has no non-null points.
    """
    values = sorted(series.values())
    if not values:
        raise ValueError(
            f"No non-null points in series {series.name!r}; cannot compute utilization."
        )
    return UtilizationStats(
        sample_count=len(values),
        avg=sum(values) / len(values),
        p50=_percentile(values, 50),
        p95=_percentile(values, 95),
        p99=_percentile(values, 99),
        max=values[-1],
        min=values[0],
    )


# Classifier: methodology + thresholds in ADR-0011. Cutoffs are config-injected (tunable).
# Capacity-materiality severity is shared with DX-004 via framework/materiality (ADR-0012).


@dataclass(frozen=True)
class OverProvisioningConfig:
    """Tunable knobs for the over-provisioning verdict (defaults per ADR-0011).

    band_statistic: which ``UtilizationStats`` field drives the trigger. Default
        ``p99`` (NOT p95/avg): for *throughput*, the high percentile matters because
        peaking near 100% means throttling. Recommending a downsize off p95 would
        risk telling a customer to cut capacity they actually need at peak. The
        threshold sweep (incl. a bursty fixture) is what will confirm p95 vs p99.
    min_ru: Manual-throughput recommendation minimum only. Autoscale uses the separate
        ``AUTOSCALE_MIN_MAX_RU`` baseline; neither is an autoscale idle billing floor.
    """

    band_statistic: str = "p99"
    idle_pct: float = 1.0
    low_pct: float = 10.0
    moderate_pct: float = 30.0
    min_ru: int = 400
    headroom: float = 1.3
    # Peak-saturation guard: if the busiest sample (``stats.max``) consumed at least this % of
    # provisioned capacity, the container genuinely needs that capacity at peak (a recurring batch /
    # burst) — so it is NOT flagged over-provisioned even when the P99 band is low. This prevents
    # recommending a downsize that would throttle a real spike (see #5).
    peak_saturation_pct: float = 90.0
    # Relative materiality cutoffs (wasted RU/s as % of scope provisioned RU/s) — ADR-0012.
    material_high_pct: float = 5.0
    material_med_pct: float = 1.0
    # Absolute-RU fallbacks, used only when scope provisioned RU/s is unknown.
    abs_high_ru: float = 5000.0
    abs_med_ru: float = 1000.0


@dataclass(frozen=True)
class OverProvisioningVerdict:
    """The over-provisioning finding for one container (capacity, not cost — ADR-0012)."""

    is_over_provisioned: bool
    band: str  # idle | low | moderate | ok | insufficient_data
    trigger_statistic: str
    trigger_pct: float
    provisioned_ru: float
    recommended_ru: float
    wasted_ru: float
    severity: str  # high | medium | low | none
    materiality_pct: float | None  # wasted RU/s as % of scope provisioned RU/s
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _abstain_verdict(provisioned_ru: float, *, reason: str, detail: str = "") -> OverProvisioningVerdict:
    """Build a uniform 'insufficient_data' abstention (ADR-0008)."""
    return OverProvisioningVerdict(
        is_over_provisioned=False,
        band="insufficient_data",
        trigger_statistic="",
        trigger_pct=0.0,
        provisioned_ru=provisioned_ru,
        recommended_ru=provisioned_ru,
        wasted_ru=0.0,
        severity="none",
        materiality_pct=None,
        methodology={"abstained": reason, "detail": detail},
    )


def classify(
    stats: UtilizationStats,
    provisioned_ru: float,
    *,
    config: OverProvisioningConfig | None = None,
    scope_provisioned_ru: float | None = None,
    autoscale_billing: bool = False,
) -> OverProvisioningVerdict:
    """Map a utilization distribution to an over-provisioning verdict + severity.

    Two axes: the **trigger** (band on a chosen percentile) decides *whether* it's
    over-provisioned; **severity** uses relative materiality in **capacity** terms (wasted RU/s vs
    the scope's provisioned RU/s — ADR-0012), else an absolute-RU fallback.

    Args:
        stats: Utilization distribution from :func:`utilization_stats`.
        provisioned_ru: The offer's manual provisioned RU/s or configured autoscale maximum.
        config: Tunable methodology knobs (validated defaults — ADR-0011).
        scope_provisioned_ru: Total provisioned RU/s of the **scope in view** (container, account,
            subscription, or fleet) used as the materiality denominator. The same waste is material
            against a small account but trivial against a whole fleet — significance is
            scope-relative. If ``None``, severity falls back to absolute RU/s. CODA reports
            **capacity, not cost** (ADR-0012); capacity ≠ cost across modes/regions.
        autoscale_billing: Use the separate 1000 RU/s maximum baseline and recover only the
            10%-of-maximum idle-floor delta. Targets remain analytical; resource-specific
            minima and service increments require separate validation (ADR-0016).
    """
    cfg = config or OverProvisioningConfig()

    # Defensive: can't compute a verdict from zero samples. Primary data-sufficiency (span +
    # min-points over the window) is checked in detect_over_provisioning via the shared
    # evaluator (ADR-0008).
    if stats.sample_count == 0:
        return _abstain_verdict(provisioned_ru, reason="no_samples")

    trigger = getattr(stats, cfg.band_statistic)

    # Peak-saturation guard (#5): a workload whose busiest sample saturates provisioned capacity
    # genuinely needs it at peak (e.g. a recurring batch job). Do not flag such a container
    # over-provisioned off a low P99 — recommending a downsize would throttle the spike.
    peak_saturates = stats.max >= cfg.peak_saturation_pct

    if peak_saturates:
        band = "ok"
    elif trigger < cfg.idle_pct:
        band = "idle"
    elif trigger < cfg.low_pct:
        band = "low"
    elif trigger < cfg.moderate_pct:
        band = "moderate"
    else:
        band = "ok"
    is_over = band != "ok"

    # Right-size target: cover the observed peak (trigger) plus headroom, never below the platform
    # minimum, never above what's already provisioned — and (#5) never below the busiest observed
    # sample, so the recommendation can never throttle a real spike.
    consumed_at_trigger = trigger / 100.0 * provisioned_ru
    peak_consumed = stats.max / 100.0 * provisioned_ru
    min_ru = AUTOSCALE_MIN_MAX_RU if autoscale_billing else cfg.min_ru
    recommended = min(
        provisioned_ru,
        max(
            float(min_ru),
            math.ceil(consumed_at_trigger * cfg.headroom),
            math.ceil(peak_consumed),
        ),
    )
    wasted_ru = max(0.0, provisioned_ru - recommended)
    recoverable_basis = "manual_full_provisioned"
    if autoscale_billing:
        # Autoscale bills, per hour, the RU/s provisioned between the 10% floor and the configured max
        # — scaled to demand. An over-high **max** therefore does NOT waste the full headroom (demand
        # between floor and peak is billed regardless of the max); it only wastes the **idle floor**
        # (10% of max, billed even at zero load). So the recoverable capacity from lowering the max is
        # the floor reduction, not (max - recommended) — using the manual formula here over-claims by
        # ~10x (see ADR-0016). Floor = 10% of max: the 1000 minimum max scales down to 100,
        # independent of the manual 400 minimum. This is not an hourly bill simulation.
        wasted_ru = max(0.0, 0.10 * provisioned_ru - 0.10 * recommended)
        recoverable_basis = "autoscale_idle_floor"

    # Severity via the shared capacity-materiality model (framework/materiality), so DX-001 and
    # DX-004 stay consistent. 'applicable' gates the "ok" (not-over-provisioned) case to "none".
    mat_cfg = MaterialityConfig(
        material_high_pct=cfg.material_high_pct,
        material_med_pct=cfg.material_med_pct,
        abs_high_ru=cfg.abs_high_ru,
        abs_med_ru=cfg.abs_med_ru,
    )
    severity, materiality_pct = materiality_severity(
        wasted_ru, scope_provisioned_ru, mat_cfg, applicable=is_over
    )

    return OverProvisioningVerdict(
        is_over_provisioned=is_over,
        band=band,
        trigger_statistic=cfg.band_statistic,
        trigger_pct=trigger,
        provisioned_ru=provisioned_ru,
        recommended_ru=recommended,
        wasted_ru=wasted_ru,
        severity=severity,
        materiality_pct=(round(materiality_pct, 2) if materiality_pct is not None else None),
        methodology={
            "band_statistic": cfg.band_statistic,
            "bands_pct": {"idle": cfg.idle_pct, "low": cfg.low_pct, "moderate": cfg.moderate_pct},
            "headroom": cfg.headroom,
            "min_ru": min_ru,
            "peak_pct": stats.max,
            "peak_saturation_pct": cfg.peak_saturation_pct,
            "peak_saturates": peak_saturates,
            "recoverable_basis": recoverable_basis,
            "severity_basis": "capacity_materiality" if scope_provisioned_ru else "absolute_ru",
        },
    )


# DX-001 §B4: over-provisioning needs ~30 days of history to capture monthly cycles; below a
# 7-day confidence floor we abstain (ADR-0008). PT1H granularity suits a 30-day window.
DATA_REQUIREMENT = DataRequirement(window_floor=timedelta(days=7), min_points=24)
PRODUCTION_WINDOW_DAYS = 30
PRODUCTION_GRANULARITY = timedelta(hours=1)


def production_window(now: datetime | None = None) -> TimeWindow:
    """The production DX-001 window: 30 days ending now, hourly buckets (DX-001 §B4)."""
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=PRODUCTION_WINDOW_DAYS), anchor, PRODUCTION_GRANULARITY)


def detect_over_provisioning(
    provider: DataProvider,
    account_resource_id: str,
    database: str,
    container: str,
    provisioned_ru: float,
    window: TimeWindow,
    *,
    config: OverProvisioningConfig | None = None,
    scope_provisioned_ru: float | None = None,
    resource_created_at: datetime | None = None,
) -> OverProvisioningVerdict:
    """End-to-end DX-001 detection for one container offer.

    Scopes telemetry by BOTH ``DatabaseName`` and ``CollectionName`` — collection names can
    repeat across databases within one account, so filtering on collection alone would merge
    unrelated containers (DX-001 §B1). Reads ``NormalizedRUConsumption`` as the per-minute
    Maximum, computes the utilization distribution, and classifies.

    ``provisioned_ru`` MUST be the user-configured value from ARM — the *metric's* provisioned
    value is an internal burst ceiling, not what the customer set (DX-001 §B2). No telemetry
    in-window yields an ``insufficient_data`` abstention (confirming idle is DX-004's job).
    """
    if resource_created_at is not None:
        age_insuff = evaluate_age(resource_created_at, window.end, DATA_REQUIREMENT.window_floor)
        if age_insuff is not None:
            return _abstain_verdict(provisioned_ru, reason=age_insuff.reason, detail=age_insuff.detail)

    series = provider.get_metric(
        account_resource_id,
        "NormalizedRUConsumption",
        window,
        aggregation="Maximum",
        dimension_filter=({"DatabaseName": database} if container is None else
                          {"DatabaseName": database, "CollectionName": container}),
    )
    insufficiency = evaluate_series(series, DATA_REQUIREMENT)
    if insufficiency is not None:
        return _abstain_verdict(provisioned_ru, reason=insufficiency.reason, detail=insufficiency.detail)

    stats = utilization_stats(series)
    return classify(
        stats, provisioned_ru, config=config, scope_provisioned_ru=scope_provisioned_ru,
    )

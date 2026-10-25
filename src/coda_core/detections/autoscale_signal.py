"""Autoscale provisioning signal + DX-011 (autoscale max over-provisioned).

For **autoscale**, ``NormalizedRUConsumption`` measures consumed RU against the *currently-scaled*
value, not the configured max — so it cannot tell whether the **max** is set too high (an idle
autoscale container scales its denominator down and still reads a low %). The correct signal is
``AutoscaledRU`` — what autoscale *actually provisioned* moment to moment — expressed as a **percentage
of the configured max**. That series answers both autoscale right-sizing questions and can be fed to
the existing classifiers:

* **DX-011** (this module): the busiest the workload ever pushed autoscale (max of AutoscaledRU-%-of-max)
  stays well below the max -> the max is over-provisioned -> lower it. Reuses DX-001's classifier
  (``over_provisioning.classify``) on the autoscale series, so the bands, headroom, and
  capacity-materiality severity (ADR-0011/0012) are shared.
* **DX-013** (``mode_switch``): the same series, read for its *duty cycle* — sustained near the max with
  little spikiness -> manual would be cheaper.

``AutoscaledRU`` carries a ``PhysicalPartitionId`` dimension; the container-level provisioned value at
an instant is the **sum across partitions**, so the series sums per timestamp before normalising.
Read-only / diagnose-only.
"""

from __future__ import annotations

from datetime import datetime

from coda_core.detections.over_provisioning import (
    DATA_REQUIREMENT,
    OverProvisioningConfig,
    OverProvisioningVerdict,
    _abstain_verdict,
    classify,
    utilization_stats,
)
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricPoint, MetricSeries, TimeWindow
from coda_core.sufficiency import evaluate_age, evaluate_series


def autoscaled_utilization_series(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    configured_max_ru: float,
    window: TimeWindow,
) -> MetricSeries:
    """Container-total ``AutoscaledRU`` as a % of the configured max, per timestamp.

    Sums the per-physical-partition AutoscaledRU at each timestamp (the container's provisioned value
    is the sum across partitions), then normalises by the configured max so the result is a 0..100
    "how much of the max was provisioned" series — directly comparable to DX-001's utilization.
    """
    per_partition = metrics.get_metric_split(
        account_resource_id, "AutoscaledRU", window,
        split_dimension="PhysicalPartitionId",
        dimension_filter=({"DatabaseName": database} if container is None else
                          {"DatabaseName": database, "CollectionName": container}),
        aggregation="Maximum",
    )
    totals: dict[datetime, float] = {}
    for series in per_partition.values():
        for p in series.points:
            if p.value is not None:
                totals[p.timestamp] = totals.get(p.timestamp, 0.0) + p.value
    scale = (100.0 / configured_max_ru) if configured_max_ru else 0.0
    points = tuple(
        MetricPoint(ts, totals[ts] * scale) for ts in sorted(totals)
    )
    return MetricSeries("AutoscaledRUUtilization", "Maximum", "Percent", points)


def detect_autoscale_max_over_provisioned(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    configured_max_ru: float,
    window: TimeWindow,
    *,
    config: OverProvisioningConfig | None = None,
    scope_provisioned_ru: float | None = None,
    resource_created_at: datetime | None = None,
) -> OverProvisioningVerdict:
    """DX-011: is the autoscale **max** set too high relative to what autoscale ever provisioned?"""
    # Band on the PEAK (max), not p99: for autoscale the max must cover legitimate spikes (that is
    # autoscale's purpose), and lowering it below a real peak would throttle it. An over-high max only
    # wastes the idle floor (10% of max billed even when idle), so we recommend lowering it to the
    # peak-provisioned level + headroom — never below what the workload actually reached.
    cfg = config or OverProvisioningConfig(band_statistic="max")
    if resource_created_at is not None:
        age = evaluate_age(resource_created_at, window.end, DATA_REQUIREMENT.window_floor)
        if age is not None:
            return _abstain_verdict(configured_max_ru, reason=age.reason, detail=age.detail)

    series = autoscaled_utilization_series(
        metrics, account_resource_id, database, container, configured_max_ru, window
    )
    insuff = evaluate_series(series, DATA_REQUIREMENT)
    if insuff is not None:
        return _abstain_verdict(configured_max_ru, reason=insuff.reason, detail=insuff.detail)

    stats = utilization_stats(series)
    # Reuse the DX-001 classifier on the autoscale series: the trigger band on PEAK AutoscaledRU-%-of-max
    # decides whether the max is over-provisioned; recommended = peak-provisioned × headroom. Bill on the
    # autoscale basis so the recoverable RU/s is the idle-floor reduction (10% of the delta), not the
    # full headroom — autoscale only bills consumption between the floor and the max (see dx-011 doc).
    return classify(stats, configured_max_ru, config=cfg, scope_provisioned_ru=scope_provisioned_ru,
                    autoscale_billing=True)

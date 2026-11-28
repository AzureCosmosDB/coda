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
* **DX-013** (``mode_switch``): compare measured hourly provisioning with fixed manual throughput
  at the same capacity and applicable billing factors.

``AutoscaledRU`` carries a ``PhysicalPartitionId`` dimension; the container-level provisioned value at
an instant is the **sum across partitions**, so the series sums per timestamp before normalising.
Read-only / diagnose-only.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from math import isfinite

from coda_core.detections.over_provisioning import (
    OverProvisioningConfig,
    OverProvisioningVerdict,
    _abstain_verdict,
    assess_sizing,
)
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricPoint, MetricSeries, TimeWindow
from coda_core.providers.shared_offer import IncompletePool, PoolMembers, verified_members


def autoscaled_utilization_series(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str | None,
    configured_max_ru: float,
    window: TimeWindow,
    *, region: str | None = None,
) -> MetricSeries:
    """Container-total ``AutoscaledRU`` as a % of the configured max, per timestamp.

    Sums the per-physical-partition AutoscaledRU at each timestamp (the container's provisioned value
    is the sum across partitions), then normalises by the configured max so the result is a 0..100
    "how much of the max was provisioned" series — directly comparable to DX-001's utilization.
    """
    scope = {"DatabaseName": database}
    if container is not None:
        scope["CollectionName"] = container
    if region is not None:
        scope["Region"] = region
    per_partition = metrics.get_metric_split(
        account_resource_id, "AutoscaledRU", window,
        split_dimension="PhysicalPartitionId",
        dimension_filter=scope,
        aggregation="Maximum",
    )
    values = defaultdict(list)
    for series in per_partition.values():
        seen = set()
        for p in series.points:
            if p.timestamp in seen:
                values[p.timestamp].append(None)
            elif p.value is not None:
                values[p.timestamp].append(p.value)
            seen.add(p.timestamp)
    points = []
    if values and configured_max_ru > 0:
        # A silent partition may be absent from the entire split, not merely from one timestamp.
        # Verify the independent count at its native grain throughout each scaled bucket.
        grain = timedelta(minutes=5)
        counts = metrics.get_metric(account_resource_id, "PhysicalPartitionCount",
                                    TimeWindow(window.start, window.end, grain),
                                    dimension_filter=scope, aggregation="Maximum", require_single_series=True)
        expected = {}
        for p in counts.points:
            expected[p.timestamp] = p.value if p.timestamp not in expected else None
        n = max(1, window.granularity // grain)
        for ts, parts in sorted(values.items()):
            if not parts or any(v is None or not isfinite(v) or v < 0 for v in parts):
                continue
            start = ts - timedelta(minutes=ts.minute % 5, seconds=ts.second, microseconds=ts.microsecond)
            if all(expected.get(start + i * grain) == len(parts) for i in range(n)):
                points.append(MetricPoint(ts, sum(parts) / configured_max_ru * 100))
    return MetricSeries("AutoscaledRUUtilization", "Maximum", "Percent", tuple(points))


def detect_autoscale_max_over_provisioned(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str | None,
    configured_max_ru: float,
    window: TimeWindow,
    *,
    config: OverProvisioningConfig | None = None,
    scope_provisioned_ru: float | None = None,
    resource_created_at: datetime | None = None,
    pool_members: PoolMembers | None = None,
) -> OverProvisioningVerdict:
    """Compare an autoscale offer's maximum with its observed peak, including shared databases.

    The shared classifier separates the 1000 RU/s maximum baseline from the 10% idle floor.
    It retains analytical sizing, not service-increment or resource-specific eligibility checks.
    """
    # Band on the PEAK (max), not p99: for autoscale the max must cover legitimate spikes (that is
    # autoscale's purpose), and lowering it below a real peak would throttle it. An over-high max only
    # wastes the idle floor (10% of max billed even when idle), so we recommend lowering it to the
    # peak-provisioned level + headroom — never below what the workload actually reached.
    cfg = config or OverProvisioningConfig(band_statistic="max")
    if container is None:
        try:
            verified_members(pool_members)
            if pool_members is not None and pool_members.dedicated:
                raise IncompletePool("AutoscaledRU cannot isolate the shared offer in this mixed database")
        except IncompletePool as exc:
            return _abstain_verdict(configured_max_ru, reason=exc.reason, detail=str(exc))
    series = autoscaled_utilization_series(
        metrics, account_resource_id, database, container, configured_max_ru, window
    )
    return assess_sizing(series, window, configured_max_ru, config=cfg, scope_provisioned_ru=scope_provisioned_ru,
                         resource_created_at=resource_created_at, autoscale_billing=True)

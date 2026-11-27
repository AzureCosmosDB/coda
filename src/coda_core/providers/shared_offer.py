"""Select directly attributable pool metrics or sum only verified member traffic (ADR-0078)."""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from math import isfinite

from azure.core.exceptions import AzureError

from .arm import PoolMembers
from .base import DataProvider, MetricPoint, MetricSeries, TimeWindow
from .monitor_retry import MonitorUnavailable


class IncompletePool(ValueError):
    """A pool-dependent result cannot be established; independent checks can continue."""

    reason = "incomplete_shared_pool"


class MissingMemberSamples(IncompletePool):
    """A successful but empty member read is distinct from an Azure read failure."""

    reason = "no_data"

def verified_members(pool: PoolMembers | None) -> tuple[str, ...]:
    """Never infer membership from missing ARM reads, nor count the same allocation twice."""
    if pool is None or pool.unresolved:
        raise IncompletePool("Shared-pool membership is incomplete")
    names = pool.shared + pool.dedicated
    if len(names) != len(set(names)) or not all(names):
        raise IncompletePool("Shared-pool membership is ambiguous")
    return pool.shared


def owner_scope(database: str, container: str | None, owner_rid: str | None) -> dict[str, str]:
    """Owner-native metrics do not depend on individual member reads."""
    if container is not None:
        return {"DatabaseName": database, "CollectionName": container}
    if not owner_rid:
        raise IncompletePool("Shared throughput owner identity is unavailable")
    return {"DatabaseName": database, "OfferOwnerRid": owner_rid}


def traffic_metric(metrics, rid: str, metric: str, window: TimeWindow, *, database: str,
                   container: str | None, pool: PoolMembers | None, aggregation: str,
                   status: str | None = None) -> MetricSeries:
    """Sum by matching timestamp, never turning a missing shared member into observed zero."""
    scope = {"DatabaseName": database}
    if status:
        scope["StatusCode"] = status
    if container is not None:
        return metrics.get_metric(rid, metric, window, aggregation=aggregation,
                                  dimension_filter={**scope, "CollectionName": container})
    members = verified_members(pool)
    if not members:
        raise IncompletePool("No verified members with shared-pool traffic")
    totals: dict = {}
    unit = None
    for name in members:
        try:
            series = metrics.get_metric(rid, metric, window, aggregation=aggregation,
                                        dimension_filter={**scope, "CollectionName": name})
        except AzureError as exc:
            detail = str(exc) if isinstance(exc, MonitorUnavailable) else type(exc).__name__
            raise IncompletePool(f"{metric} read failed for shared member {name}: "
                                 f"{detail}") from exc
        values = {p.timestamp: p.value for p in series.points if p.value is not None}
        if not values:
            raise MissingMemberSamples(f"No usable {metric} samples for shared member {name}")
        if any(not isfinite(v) or v < 0 for v in values.values()):
            raise IncompletePool(f"Invalid {metric} samples for shared member {name}")
        if not totals:
            totals = values
            unit = series.unit
        elif totals.keys() != values.keys():
            raise IncompletePool(f"Incomplete shared-member bucket coverage for {metric}")
        else:
            for ts, value in values.items():
                totals[ts] += value
    return MetricSeries(metric, aggregation, unit,
                        tuple(MetricPoint(ts, v) for ts, v in sorted(totals.items())))


def request_series(metrics: DataProvider, rid: str, window: TimeWindow, database: str,
                   container: str | None, pool: PoolMembers | None) -> tuple[MetricSeries, MetricSeries]:
    """Only compare shared 429 and total counts from the same member set and time buckets."""
    def read(status):
        return traffic_metric(metrics, rid, "TotalRequests", window, database=database,
                              container=container, pool=pool, aggregation="Count", status=status)
    total, throttled = read(None), read("429")
    if container is None:
        totals = {p.timestamp: p.value for p in total.points}
        counts = {p.timestamp: p.value for p in throttled.points}
        if totals.keys() != counts.keys() or any(counts[t] > totals[t] for t in totals):
            raise IncompletePool("Inconsistent shared-member request and 429 coverage")
    return total, throttled


RequestCounts = Callable[[TimeWindow], tuple[MetricSeries, MetricSeries]]


def offer_request_counts(metrics: DataProvider, rid: str, database: str, container: str | None,
                         members: PoolMembers | None) -> RequestCounts:
    """Lazily reuse a successful pair within one offer task; failures are not cached."""
    @lru_cache(maxsize=1)
    def read(window: TimeWindow) -> tuple[MetricSeries, MetricSeries]:
        return request_series(metrics, rid, window, database, container, members)
    return read

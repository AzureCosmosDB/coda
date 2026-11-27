"""Azure Monitor Metrics provider.

Reads Cosmos DB platform metrics (e.g. ``NormalizedRUConsumption``,
``ProvisionedThroughput``, ``TotalRequests``) for a customer account via the
Azure Monitor Metrics API. Auth is Entra ID only (no account keys) — the caller
injects a ``TokenCredential`` (``DefaultAzureCredential`` locally; OBO in the
service).

Retention reality (verified against Azure docs, to be re-confirmed empirically by
the Phase 0 measurement): platform metrics are retained ~93 days at 1-minute
granularity. That bounds how long a generated fixture stays queryable before it
must be regenerated.
"""

from __future__ import annotations

from collections import OrderedDict
from copy import copy
from azure.core.credentials import TokenCredential
from azure.monitor.query import MetricAggregationType, MetricsQueryClient

from coda_core.detections.pitr_savings import DataUsageSample

from .base import DataProvider, MetricPoint, MetricSeries, TimeWindow
from .indexing_batch import IndexingReadPlan, plan_names
from .monitor_retry import MonitorCooldown, MonitorReadClient, RetryBudget
from .monitor_cohort import CohortClient
from .partition_metrics import (
    SERIES_LIMIT, PartitionReader, RegionHistory, metadata as _metadata, quote, split_series,
)

# Map our aggregation names to the SDK enum. Kept explicit so callers use a small,
# stable vocabulary rather than the SDK's types.
_AGGREGATION = {
    "Average": MetricAggregationType.AVERAGE,
    "Maximum": MetricAggregationType.MAXIMUM,
    "Minimum": MetricAggregationType.MINIMUM,
    "Total": MetricAggregationType.TOTAL,
    "Count": MetricAggregationType.COUNT,
}


def _reduce(values: list[float], aggregation: str) -> float:
    """Combine several same-timestamp values into one, per aggregation semantics.

    A dimension-filtered Cosmos metric can still return multiple timeseries for one
    timestamp (e.g. one per physical partition / region). We collapse them the way the
    aggregation implies: Maximum -> max (the hottest partition, which is what
    NormalizedRUConsumption is about), Minimum -> min, Average -> mean, and
    Total/Count -> sum.
    """
    if aggregation == "Maximum":
        return max(values)
    if aggregation == "Minimum":
        return min(values)
    if aggregation == "Average":
        return sum(values) / len(values)
    return sum(values)  # Total, Count


class AzureMonitorMetricsProvider(DataProvider):
    """DataProvider backed by the Azure Monitor Metrics API."""

    def __init__(self, credential: TokenCredential, *, cooldown: MonitorCooldown | None = None,
                 budget: RetryBudget | None = None) -> None:
        self._credential = credential
        self._external_cooldown = cooldown is not None
        self._external_budget = budget is not None
        self.cooldown = cooldown or MonitorCooldown()
        self.budget = budget or RetryBudget()
        self._client = MonitorReadClient(MetricsQueryClient(credential), self.cooldown, self.budget)
        self._partitions = PartitionReader(self._client)
        self._exact = None

    @property
    def credential(self) -> TokenCredential:
        """Credential used to create per-worker clients without sharing SDK client state."""
        return self._credential

    def indexing_plan(self, resource_id: str, window: TimeWindow) -> IndexingReadPlan:
        """Create an independent indexing projection and recovery budget for this report."""
        return IndexingReadPlan(self._client, resource_id, window)

    def for_cohort(self, database, containers=(), owners=()):
        """Use a bounded projection on this worker's SDK client, never sharing it across threads."""
        scoped = copy(self)
        scoped._client = CohortClient(self._client, database, containers, owners)
        scoped._partitions = PartitionReader(scoped._client)
        scoped._exact = OrderedDict()
        return scoped

    def for_report(self):
        """Keep caller-owned retry state; reset each provider-owned component for this report."""
        if self._external_cooldown and self._external_budget:
            return self
        scoped = copy(self)
        if not self._external_cooldown:
            scoped.cooldown = MonitorCooldown()
        if not self._external_budget:
            scoped.budget = RetryBudget()
        scoped._client = MonitorReadClient(self._client.client, scoped.cooldown, scoped.budget)
        scoped._partitions = PartitionReader(scoped._client)
        return scoped

    def _remember(self, key, result):
        """Only share nonempty successfully decoded histories, never failures or indices across reports."""
        cache = getattr(self, "_exact", None)
        if cache is not None:
            if len(cache) >= 64:
                cache.popitem(last=False)
            cache[key] = result

    def get_metric(
        self,
        resource_id: str,
        metric_name: str,
        window: TimeWindow,
        *,
        aggregation: str = "Average",
        dimension_filter: dict[str, str] | None = None,
    ) -> MetricSeries:
        """Query one Cosmos metric as a time series over an absolute window.

        Args:
            resource_id: Full ARM resource id of the Cosmos DB account.
            metric_name: Azure Monitor metric name (namespace
                ``Microsoft.DocumentDB/databaseAccounts``).
            window: Absolute ``[start, end]`` + granularity to aggregate over.
            aggregation: One of the keys in ``_AGGREGATION``.
            dimension_filter: Optional equality filter on metric dimensions, e.g.
                ``{"CollectionName": "overprovisioned-001"}`` to scope to one container.
        """
        if aggregation not in _AGGREGATION:
            raise ValueError(
                f"Unsupported aggregation {aggregation!r}; "
                f"expected one of {sorted(_AGGREGATION)}."
            )
        key = (resource_id, metric_name, window, aggregation, tuple(sorted((dimension_filter or {}).items())), None)
        cache = getattr(self, "_exact", None)
        if cache is not None and key in cache:
            return cache[key]

        # Azure Monitor metric filter syntax: "Dim1 eq 'v1' and Dim2 eq 'v2'".
        metric_filter = None
        if dimension_filter:
            metric_filter = " and ".join(f"{k} eq {quote(v)}" for k, v in dimension_filter.items())

        response = self._client.query_resource(
            resource_id,
            metric_names=[metric_name],
            # The Metrics API accepts an explicit (start, end) tuple as the timespan.
            timespan=(window.start, window.end),
            granularity=window.granularity,
            aggregations=[_AGGREGATION[aggregation]],
            filter=metric_filter,
        )

        # Collect raw values keyed by timestamp; a filtered query may still return
        # several timeseries (per partition/region), so we reduce per timestamp below.
        by_ts: dict = {}
        unit: str | None = None
        for metric in response.metrics:
            unit = str(metric.unit) if metric.unit is not None else None
            for ts in metric.timeseries:
                for datum in ts.data:
                    value = getattr(datum, aggregation.lower(), None)
                    if value is not None:
                        by_ts.setdefault(datum.timestamp, []).append(value)

        points = [
            MetricPoint(timestamp=ts, value=_reduce(vals, aggregation))
            for ts, vals in sorted(by_ts.items())
        ]
        series = MetricSeries(
            name=metric_name,
            aggregation=aggregation,
            unit=unit,
            points=tuple(points),
        )
        if points and metric_name in {"NormalizedRUConsumption", "TotalRequests"}:
            self._remember(key, series)
        return series

    def get_metric_split(
        self,
        resource_id: str,
        metric_name: str,
        window: TimeWindow,
        *,
        split_dimension: str,
        dimension_filter: dict[str, str] | None = None,
        aggregation: str = "Average",
    ) -> dict[str, MetricSeries]:
        """Return one :class:`MetricSeries` per value of ``split_dimension``.

        Unlike :meth:`get_metric` (which collapses all timeseries into one), this keeps them
        separate — e.g. split ``NormalizedRUConsumption`` by ``PhysicalPartitionId`` to assess
        per-partition uniformity (global under-provisioning vs a hot partition). Implemented via
        the Azure Monitor ``Dimension eq '*'`` filter, which returns one timeseries per value.
        """
        if aggregation not in _AGGREGATION:
            raise ValueError(f"Unsupported aggregation {aggregation!r}.")

        clauses = [f"{k} eq {quote(v)}" for k, v in (dimension_filter or {}).items()]
        key = (resource_id, metric_name, window, aggregation, tuple(sorted((dimension_filter or {}).items())), split_dimension)
        cache = getattr(self, "_exact", None)
        if cache is not None and key in cache:
            return cache[key].copy()
        clauses.append(f"{split_dimension} eq '*'")
        response = self._client.query_resource(
            resource_id,
            metric_names=[metric_name],
            timespan=(window.start, window.end),
            granularity=window.granularity,
            aggregations=[_AGGREGATION[aggregation]],
            filter=" and ".join(clauses),
            max_results=SERIES_LIMIT,
        )
        rows = [ts for metric in response.metrics for ts in metric.timeseries]
        out, conflicts, unknown = split_series(rows, metric_name, aggregation, split_dimension)
        if conflicts or unknown or len(rows) >= SERIES_LIMIT:
            raise ValueError(f"Incomplete or ambiguous {metric_name} split by {split_dimension}")
        unit = next((str(m.unit) for m in response.metrics if m.unit is not None), None)
        result = {k: MetricSeries(s.name, s.aggregation, unit, s.points) for k, s in out.items()}
        if result and all(s.points for s in result.values()) and metric_name in {"AutoscaledRU", "TotalRequests"}:
            self._remember(key, result.copy())
        return result

    def partition_histories(self, rid: str, metric: str, window: TimeWindow, *,
                            database: str, container: str | None, owner_rid: str | None,
                            regions: tuple[str | None, ...]) -> tuple[RegionHistory, ...]:
        """Read comparable physical-partition evidence independently in every configured region."""
        return tuple(self._partitions.region(rid, database, container, owner_rid, region,
                                             window, metric) if region else
                     RegionHistory("Unidentified ARM region", None, 0, {}, ("region_name_missing",),
                                   window.granularity)
                     for region in regions)

    def get_data_usage_v2_samples(
        self,
        resource_id: str,
        window: TimeWindow,
        *,
        reference_region: str,
        expected_containers: tuple[tuple[str, str], ...] = (),
    ) -> tuple[DataUsageSample, ...]:
        """Read raw ``DataUsageV2`` logical-container series from exactly one account region.

        The method deliberately does not collapse series or timestamps. DX-019's pure snapshot
        selector can therefore prove that one timestamp contains every ARM-inventoried logical
        container exactly once before summing the byte values.
        """
        prefix = f"Region eq {quote(reference_region)} and "
        if len(expected_containers) >= SERIES_LIMIT:
            samples = []
            for batch in plan_names(expected_containers):
                if not batch.fits():
                    raise ValueError("DataUsageV2 inventory exceeds encoded filter size")
                rows = self._storage_rows(resource_id, window, prefix + batch.filter, len(batch.containers) + 1)
                if any(row.database != batch.database or row.container not in batch.containers for row in rows):
                    raise ValueError("DataUsageV2 returned a series outside its group")
                samples.extend(rows)
            return tuple(samples)
        return self._storage_rows(resource_id, window, prefix + "DatabaseName eq '*' and CollectionName eq '*'", SERIES_LIMIT)

    def _storage_rows(self, resource_id, window, scope, top):
        """Keep raw dimensions and timestamps; the snapshot selector checks the complete union."""
        response = self._client.query_resource(
            resource_id,
            metric_names=["DataUsageV2"],
            timespan=(window.start, window.end),
            granularity=window.granularity,
            aggregations=[MetricAggregationType.TOTAL],
            max_results=top,
            filter=scope,
        )
        samples: list[DataUsageSample] = []
        for metric in response.metrics:
            unit = str(metric.unit or "")
            if "byte" not in unit.casefold():
                raise ValueError(f"DataUsageV2 returned non-byte unit {unit!r}")
            for timeseries in metric.timeseries:
                meta = _metadata(timeseries)
                for datum in timeseries.data:
                    value = getattr(datum, "total", None)
                    if value is not None:
                        samples.append(DataUsageSample(
                            timestamp=datum.timestamp,
                            database=meta.get("databasename", ""),
                            container=meta.get("collectionname", ""),
                            region=meta.get("region", ""),
                            bytes_used=float(value),
                        ))
        return tuple(samples)

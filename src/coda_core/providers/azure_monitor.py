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

from azure.core.credentials import TokenCredential
from azure.monitor.query import MetricAggregationType, MetricsQueryClient

from coda_core.detections.pitr_savings import DataUsageSample

from .base import DataProvider, MetricPoint, MetricSeries, TimeWindow

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


def _metadata(ts) -> dict[str, str]:
    """Normalize both SDK metadata shapes into dimension-name/value strings."""
    raw = getattr(ts, "metadata_values", None)
    if isinstance(raw, dict):
        return {
            str(key).casefold(): str(getattr(value, "value", value))
            for key, value in raw.items()
        }
    out: dict[str, str] = {}
    for item in raw or []:
        name = getattr(getattr(item, "name", None), "value", None)
        value = getattr(item, "value", None)
        if name is not None and value is not None:
            out[str(name).casefold()] = str(value)
    return out


class AzureMonitorMetricsProvider(DataProvider):
    """DataProvider backed by the Azure Monitor Metrics API."""

    def __init__(self, credential: TokenCredential) -> None:
        self._credential = credential
        # MetricsQueryClient targets the public Azure Monitor endpoint by default.
        self._client = MetricsQueryClient(credential)

    @property
    def credential(self) -> TokenCredential:
        """Credential used to create per-worker clients without sharing SDK client state."""
        return self._credential

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

        # Azure Monitor metric filter syntax: "Dim1 eq 'v1' and Dim2 eq 'v2'".
        metric_filter = None
        if dimension_filter:
            metric_filter = " and ".join(f"{k} eq '{v}'" for k, v in dimension_filter.items())

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
        return MetricSeries(
            name=metric_name,
            aggregation=aggregation,
            unit=unit,
            points=tuple(points),
        )

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

        clauses = [f"{k} eq '{v}'" for k, v in (dimension_filter or {}).items()]
        clauses.append(f"{split_dimension} eq '*'")
        response = self._client.query_resource(
            resource_id,
            metric_names=[metric_name],
            timespan=(window.start, window.end),
            granularity=window.granularity,
            aggregations=[_AGGREGATION[aggregation]],
            filter=" and ".join(clauses),
        )

        out: dict[str, MetricSeries] = {}
        for metric in response.metrics:
            unit = str(metric.unit) if metric.unit is not None else None
            for ts in metric.timeseries:
                # metadata_values is a dict of lowercased dimension name -> value.
                meta = ts.metadata_values if isinstance(ts.metadata_values, dict) else {}
                key = meta.get(split_dimension.lower(), "unknown")
                points = [
                    MetricPoint(timestamp=d.timestamp, value=getattr(d, aggregation.lower(), None))
                    for d in ts.data
                ]
                points = [p for p in points if p.value is not None]
                points.sort(key=lambda p: p.timestamp)
                out[key] = MetricSeries(
                    name=metric_name, aggregation=aggregation, unit=unit, points=tuple(points)
                )
        return out

    def get_data_usage_v2_samples(
        self,
        resource_id: str,
        window: TimeWindow,
        *,
        reference_region: str,
    ) -> tuple[DataUsageSample, ...]:
        """Read raw ``DataUsageV2`` logical-container series from exactly one account region.

        The method deliberately does not collapse series or timestamps. DX-019's pure snapshot
        selector can therefore prove that one timestamp contains every ARM-inventoried logical
        container exactly once before summing the byte values.
        """
        escaped_region = reference_region.replace("'", "''")
        response = self._client.query_resource(
            resource_id,
            metric_names=["DataUsageV2"],
            timespan=(window.start, window.end),
            granularity=window.granularity,
            aggregations=[MetricAggregationType.TOTAL],
            filter=(
                f"Region eq '{escaped_region}' and "
                "DatabaseName eq '*' and CollectionName eq '*'"
            ),
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

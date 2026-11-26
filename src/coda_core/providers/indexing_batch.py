"""Bounded, report-local DX-024 Monitor reads, projected back to exact ARM units (ADR-0081)."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from math import ceil, isfinite
from urllib.parse import quote as urlquote

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.monitor.query import MetricAggregationType, MetricsQueryClient

from coda_core.providers.arm import ContainerIndexing
from coda_core.providers.base import DataProvider, MetricPoint, MetricSeries, TimeWindow
from coda_core.providers.partition_metrics import metadata, quote

METRICS = ("IndexUsage", "DataUsage")
# Application budgets, not Azure limits. Leave room for the resource ID and other URL parameters.
MAX_CONTAINERS = 50
MAX_ENCODED_FILTER = 3500
MAX_RECOVERY_READS = 8


class IncompleteBatch(ValueError):
    """A requested unit could not be attributed safely. Never represent this as a measured zero."""


@dataclass(frozen=True)
class Batch:
    database: str
    containers: tuple[str, ...]

    @property
    def filter(self) -> str:
        """Only request named members of the report inventory, all in one database."""
        clauses = " or ".join(f"CollectionName eq {quote(c)}" for c in self.containers)
        selector = f"({clauses})" if len(self.containers) > 1 else clauses
        return f"DatabaseName eq {quote(self.database)} and {selector}"

    def fits(self) -> bool:
        """Encoded bytes, not characters, determine whether this planned GET fits our budget."""
        return (len(self.containers) <= MAX_CONTAINERS
                and len(urlquote(self.filter, safe="")) <= MAX_ENCODED_FILTER)


def plan(inventory: Sequence[ContainerIndexing]) -> Iterator[Batch]:
    """Group in stable inventory order, bounding both cardinality and encoded filter size."""
    databases: dict[str, dict[str, None]] = defaultdict(dict)
    for unit in inventory:
        if any(not name or name == "*" for name in (unit.database, unit.container)):
            raise ValueError("DX-024 requires explicit database and container names")
        if unit.container in databases[unit.database]:
            raise ValueError("Duplicate ARM container identity in DX-024 inventory")
        databases[unit.database][unit.container] = None
    for db, names in databases.items():
        group: tuple[str, ...] = ()
        for name in names:
            candidate = Batch(db, (*group, name))
            if not candidate.fits():
                if group:
                    yield Batch(db, group)
                candidate = Batch(db, (name,))
                if not candidate.fits():
                    yield candidate  # Account for the unit; do not issue an oversized query.
                    group = ()
                    continue
            group = candidate.containers
        if group:
            yield Batch(db, group)


class ProjectedReads(DataProvider):
    """A read-only projection of one batch, usable only for its exact request identities."""

    def __init__(self, rid: str, window: TimeWindow, db: str,
                 cells: dict[tuple[str, str], MetricSeries | IncompleteBatch]):
        self.rid, self.window, self.db, self.cells = rid, window, db, cells

    @classmethod
    def unavailable(cls, rid, window, database, containers, reason):
        """Carry missing evidence into the normal per-unit detector abstention path."""
        return cls(rid, window, database, {(c, m): IncompleteBatch(reason) for c in containers for m in METRICS})

    def get_metric(self, resource_id, metric_name, window, *, aggregation="Average", dimension_filter=None):
        """Serve a scoped Maximum series or expose the specific missing/failed read."""
        dims = dimension_filter or {}
        if (resource_id != self.rid or window != self.window or aggregation != "Maximum"
                or set(dims) != {"DatabaseName", "CollectionName"} or dims["DatabaseName"] != self.db):
            raise ValueError("Query does not match the DX-024 projection")
        value = self.cells[(dims["CollectionName"], metric_name)]
        if isinstance(value, IncompleteBatch):
            raise IncompleteBatch(str(value))
        return value


class IndexingReadPlan:
    """One account and absolute window. Budget and projection state never cross a report boundary."""

    def __init__(self, client: MetricsQueryClient, resource_id: str, window: TimeWindow):
        self.client, self.rid, self.window = client, resource_id, window
        self.batches = self.recoveries = 0
        self.stop_reason: str | None = None

    def _read(self, batch: Batch, metrics: tuple[str, ...], *, exact: bool):
        """Return attributed cells. Missing dictionary keys alone are eligible for exact recovery."""
        errors: dict[str, str] = {}

        def metric_status(response):
            # The installed 1.4.x public Metric model drops REST's per-metric errorCode on HTTP 200.
            if response.http_response.status_code == 200:
                for obj in json.loads(response.http_response.text()).get("value", []):
                    code = obj.get("errorCode")
                    if code and code != "Success":
                        errors[obj["name"]["value"]] = str(code)

        def unavailable(reason):
            return {(c, m): IncompleteBatch(reason) for c in batch.containers for m in metrics}

        if self.stop_reason:
            return unavailable(f"Not queried after earlier rejection: {self.stop_reason}")
        try:
            response = self.client.query_resource(
                self.rid, metric_names=list(metrics), timespan=(self.window.start, self.window.end),
                granularity=self.window.granularity, aggregations=[MetricAggregationType.MAXIMUM],
                filter=batch.filter, max_results=len(batch.containers) * len(metrics) + 1,
                raw_response_hook=metric_status, retry_total=0,
            )
        except (HttpResponseError, ServiceRequestError, ServiceResponseError) as exc:
            code = getattr(exc, "status_code", None)
            reason = f"Monitor read failed: {code or type(exc).__name__}"
            if code in {401, 403, 429}:
                self.stop_reason = reason  # Do not amplify rejection or throttling into N requests.
            return unavailable(reason)
        if response.granularity != self.window.granularity:
            return unavailable("Monitor returned a different time grain")
        try:
            interval = tuple(datetime.fromisoformat(t) for t in response.timespan.split("/"))
        except (AttributeError, ValueError):
            return unavailable("Monitor returned an unverified time span")
        requested = (self.window.start, self.window.end)
        if interval not in (requested, tuple(t.replace(microsecond=0) for t in requested)):
            return unavailable("Monitor returned a different time span")
        cells: dict[tuple[str, str], MetricSeries | IncompleteBatch] = {}
        for name in metrics:
            if name in errors:
                cells.update({(c, name): IncompleteBatch(f"{name} failed: {errors[name]}")
                              for c in batch.containers})
                continue
            matches = [metric for metric in response.metrics if metric.name == name]
            if len(matches) != 1:
                continue  # Absent/ambiguous metric does not invalidate its independently identified sibling.
            metric = matches[0]
            if metric.unit != "Bytes":
                continue
            by_name = defaultdict(list)
            ambiguous = False
            for ts in metric.timeseries:
                dims = metadata(ts)
                c = dims.get("collectionname")
                if (dims.get("databasename") != batch.database or c not in batch.containers
                        or set(dims) != {"databasename", "collectionname"}):
                    ambiguous = True
                    break
                by_name[c].append(ts)
            if ambiguous:
                continue
            for c in batch.containers:
                series = by_name[c]
                if not series and exact:
                    cells[c, name] = MetricSeries(name, "Maximum", metric.unit, ())
                if len(series) != 1:
                    continue
                points = {}
                for p in series[0].data:
                    if (p.timestamp in points or not self.window.start - self.window.granularity
                            < p.timestamp < self.window.end or (p.maximum is not None and not isfinite(p.maximum))):
                        break
                    points[p.timestamp] = p.maximum
                else:
                    # A partial time series can omit the newest usable value. Recover the original
                    # exact read rather than passing its prefix to DX-024 as the latest sample.
                    stamps = sorted(points)
                    grain = self.window.granularity
                    if not exact:
                        if not stamps or stamps[0] > self.window.start:
                            continue
                        # Azure also returns N buckets starting at the requested minute (:00),
                        # not N+1 intersecting buckets for a window starting at :17.456789.
                        minute_grid = (stamps[0] == self.window.start.replace(second=0, microsecond=0)
                                       and len(stamps) == ceil((self.window.end - self.window.start) / grain))
                        if ((stamps[-1] + grain < self.window.end and not minute_grid)
                                or any(b - a != grain for a, b in zip(stamps, stamps[1:]))):
                            continue
                    cells[c, name] = MetricSeries(name, "Maximum", metric.unit, tuple(
                        MetricPoint(t, points[t]) for t in stamps if points[t] is not None))
        return cells

    def project(self, batch: Batch) -> ProjectedReads:
        """Seed exact keys, repairing only the missing metric/container pairs within a run-wide cap."""
        if not batch.fits():
            cells = {(c, m): IncompleteBatch("Unit exceeds encoded filter budget; not queried")
                     for c in batch.containers for m in METRICS}
            return ProjectedReads(self.rid, self.window, batch.database, cells)
        if not self.stop_reason:
            self.batches += 1
        cells = self._read(batch, METRICS, exact=False)
        for c in batch.containers:
            for m in METRICS:
                if (c, m) not in cells:
                    if not self.stop_reason and self.recoveries < MAX_RECOVERY_READS:
                        self.recoveries += 1
                        cells.update(self._read(Batch(batch.database, (c,)), (m,), exact=True))
                    cells.setdefault((c, m), IncompleteBatch(self.stop_reason or
                                     "Incomplete or ambiguous Monitor series; exact recovery unavailable"))
        return ProjectedReads(self.rid, self.window, batch.database, cells)

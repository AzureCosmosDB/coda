"""Bounded, report-local DX-024 Monitor reads, projected back to exact ARM units (ADR-0081)."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from itertools import chain, islice
from math import isfinite
from threading import Lock
from urllib.parse import quote as urlquote

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.monitor.query import MetricAggregationType, MetricsQueryClient

from coda_core.providers.arm import ContainerIndexing
from coda_core.providers.base import DataProvider, MetricPoint, MetricSeries, TimeWindow, covers_bucket_grid
from coda_core.providers.monitor_retry import MonitorUnavailable
from coda_core.providers.partition_metrics import metadata, quote

METRICS = ("IndexUsage", "DataUsage")
# Application budgets, not Azure limits. Leave room for the resource ID and other URL parameters.
MAX_CONTAINERS = 50
MAX_ENCODED_FILTER = 3500
MAX_RECOVERY_READS = 8


class IncompleteBatch(ValueError):
    """A requested unit could not be attributed safely. Never represent this as a measured zero."""


class InvalidIndexingInventory(IncompleteBatch):
    """An ambiguous ARM identity cannot establish even a configuration-only result."""


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
    return plan_names((u.database, u.container) for u in inventory)


def plan_names(inventory: Iterable[tuple[str, str]]) -> Iterator[Batch]:
    """Plan named logical containers without requiring an indexing policy for storage-only reads."""
    databases: dict[str, dict[str, None]] = defaultdict(dict)
    for database, container in inventory:
        if any(not name or name == "*" for name in (database, container)):
            raise ValueError("Monitor requires explicit database and container names")
        if container in databases[database]:
            raise ValueError("Duplicate ARM container identity in Monitor inventory")
        databases[database][container] = None
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
    def unavailable(cls, rid, window, database, containers, reason, *, error_type=IncompleteBatch):
        """Carry missing evidence into the normal per-unit detector abstention path."""
        return cls(rid, window, database, {(c, m): error_type(reason) for c in containers for m in METRICS})

    def get_metric(self, resource_id, metric_name, window, *, aggregation="Average", dimension_filter=None):
        """Serve a scoped Maximum series or expose the specific missing/failed read."""
        dims = dimension_filter or {}
        if (resource_id != self.rid or window != self.window or aggregation != "Maximum"
                or set(dims) != {"DatabaseName", "CollectionName"} or dims["DatabaseName"] != self.db):
            raise ValueError("Query does not match the DX-024 projection")
        value = self.cells[(dims["CollectionName"], metric_name)]
        if isinstance(value, IncompleteBatch):
            raise type(value)(str(value))
        return value


class IndexingReadPlan:
    """One account and absolute window. Budget and projection state never cross a report boundary."""

    def __init__(self, client: MetricsQueryClient, resource_id: str, window: TimeWindow,
                 *, worker_client: Callable[[], MetricsQueryClient] | None = None):
        self.client, self.rid, self.window = client, resource_id, window
        self.worker_client = worker_client
        self._admission = Lock()
        self.batches = self.recoveries = 0
        self.stop_reason: str | None = None

    def _read(self, batch: Batch, metrics: tuple[str, ...], *, exact: bool):
        """Return attributed cells. Missing dictionary keys alone are eligible for exact recovery."""
        errors: dict[str, str] = {}

        def metric_status(response):
            # The installed 1.4.x public Metric model drops REST's per-metric errorCode on HTTP 200.
            errors.clear()  # Only the final attempt describes the returned response.
            if response.http_response.status_code == 200:
                for obj in json.loads(response.http_response.text()).get("value", []):
                    code = obj.get("errorCode")
                    if code and code != "Success":
                        errors[obj["name"]["value"]] = str(code)

        def unavailable(reason):
            return {(c, m): IncompleteBatch(reason) for c in batch.containers for m in metrics}

        with self._admission:
            if self.stop_reason:
                return unavailable(f"Not queried after earlier rejection: {self.stop_reason}")
            if not exact:
                self.batches += 1
        client = self.worker_client() if self.worker_client and not exact else self.client
        try:
            response = client.query_resource(
                self.rid, metric_names=list(metrics), timespan=(self.window.start, self.window.end),
                granularity=self.window.granularity, aggregations=[MetricAggregationType.MAXIMUM],
                filter=batch.filter, max_results=len(batch.containers) * len(metrics) + 1,
                raw_response_hook=metric_status, retry_total=0,
            )
        except (HttpResponseError, ServiceRequestError, ServiceResponseError) as exc:
            code = getattr(exc, "status_code", None)
            reason = str(exc) if isinstance(exc, MonitorUnavailable) else f"Monitor read failed: {code or type(exc).__name__}"
            if code in {401, 403, 429}:
                with self._admission:
                    self.stop_reason = self.stop_reason or reason
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
                    if not covers_bucket_grid(stamps, self.window):
                        continue
                    cells[c, name] = MetricSeries(name, "Maximum", metric.unit, tuple(
                        MetricPoint(t, points[t]) for t in stamps if points[t] is not None))
        return cells

    def _seed(self, batch):
        """Return the grouped measurements without consuming the shared recovery budget."""
        if not batch.fits():
            return {(c, m): IncompleteBatch("Unit exceeds encoded filter budget; not queried")
                    for c in batch.containers for m in METRICS}
        return self._read(batch, METRICS, exact=False)

    def _finish(self, batch, cells):
        """Recover in inventory order on one thread so the same units receive the eight reads."""
        for c in batch.containers:
            for m in METRICS:
                if (c, m) not in cells:
                    if not self.stop_reason and self.recoveries < MAX_RECOVERY_READS:
                        self.recoveries += 1
                        cells.update(self._read(Batch(batch.database, (c,)), (m,), exact=True))
                    cells.setdefault((c, m), IncompleteBatch(self.stop_reason or
                                     "Incomplete or ambiguous Monitor series; exact recovery unavailable"))
        return ProjectedReads(self.rid, self.window, batch.database, cells)

    def project(self, batch: Batch) -> ProjectedReads:
        """Read a single group with the same checks and recovery budget as the parallel pass."""
        return self._finish(batch, self._seed(batch))

    def projections(self, batches: Iterable[Batch], workers: int):
        """Overlap at most `workers` grouped reads, retaining only that many groups' histories."""
        batches = iter(batches)
        first = list(islice(batches, workers if self.worker_client else 1))

        def finish(batch, read):
            try:
                return self._finish(batch, read())
            except (ValueError, TypeError, AttributeError, KeyError) as exc:
                return ProjectedReads.unavailable(self.rid, self.window, batch.database,
                    batch.containers, f"Invalid Monitor response: {type(exc).__name__}")

        if len(first) <= 1:
            for batch in chain(first, batches):
                yield batch, finish(batch, lambda: self._seed(batch))
            return
        with ThreadPoolExecutor(max_workers=len(first)) as pool:
            pending = deque((b, pool.submit(self._seed, b)) for b in first)
            while pending:
                batch, future = pending.popleft()
                yield batch, finish(batch, future.result)
                if (b := next(batches, None)) is not None:
                    pending.append((b, pool.submit(self._seed, b)))

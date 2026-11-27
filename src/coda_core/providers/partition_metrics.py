"""Offer- and region-scoped physical-partition observations and coverage (ADR-0077)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from math import ceil, isfinite
from typing import Iterator

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.monitor.query import MetricAggregationType

from .base import MetricPoint, MetricSeries, TimeWindow
from .monitor_retry import MonitorUnavailable

SERIES_LIMIT = 1000
TARGETED_LIMIT = 4
READ_ERRORS = (HttpResponseError, ServiceRequestError, ServiceResponseError)


def quote(value: str) -> str:
    """Quote one OData dimension value without changing its identity."""
    return "'" + value.replace("'", "''") + "'"


def metadata(ts) -> dict[str, str]:
    """Normalize SDK dimension names, retaining case-sensitive values but never null IDs."""
    raw = getattr(ts, "metadata_values", None) or {}
    pairs = raw.items() if isinstance(raw, dict) else (
        (item.name.value, item.value) for item in raw
    )
    return {str(k).casefold(): str(v) for k, value in pairs
            if (v := getattr(value, "value", value)) is not None}


def split_series(rows, name: str, aggregation: str, dimension: str
                 ) -> tuple[dict[str, MetricSeries], set[str], int]:
    """Union complementary observations and identical repeats; quarantine ambiguous identities."""
    values: dict[str, dict[datetime, float]] = defaultdict(dict)
    dimensions: dict[str, dict[str, str]] = {}
    conflicts: set[str] = set()
    unidentified = 0
    for ts in rows:
        dims = metadata(ts)
        key = dims.get(dimension.casefold())
        if not key or not key.strip():
            unidentified += 1
            continue
        points = values[key]
        if dimensions.setdefault(key, dims) != dims:
            conflicts.add(key)  # Same ID, different dimensional slice: not duplicate evidence.
        for p in ts.data:
            value = getattr(p, aggregation.lower())
            if value is None:
                continue
            if not isfinite(value) or (p.timestamp in points and points[p.timestamp] != value):
                conflicts.add(key)
            else:
                points[p.timestamp] = value
    series = {k: MetricSeries(name, aggregation, None, tuple(
        MetricPoint(t, v) for t, v in sorted(points.items())
    )) for k, points in values.items() if k not in conflicts}
    return series, conflicts, unidentified


@dataclass(frozen=True)
class RegionHistory:
    """Only identified, non-conflicting series may witness a regional comparison."""

    region: str
    expected: int | None
    observed: int
    series: dict[str, MetricSeries]
    issues: tuple[str, ...]
    granularity: timedelta

    @property
    def complete(self) -> bool:
        """A negative requires known inventory, usable histories and no gaps or ambiguity."""
        return not self.issues and self.expected is not None and self.expected == len(self.series)

    def evidence(self) -> dict:
        """Counts are distinct per region; never sum replicas into a physical offer count."""
        return {"region": self.region, "expected": self.expected, "observed": self.observed,
                "usable": len(self.series), "complete": self.complete, "issues": self.issues}

    def comparisons(self) -> Iterator[dict[str, MetricSeries]]:
        """Compare coexisting IDs on matching buckets, never across a gap, split or region."""
        if not self.series:
            return
        if self.complete:
            yield self.series
            return
        buckets: dict[datetime, dict[str, MetricPoint]] = defaultdict(dict)
        for key, series in self.series.items():
            for point in series.points:
                buckets[point.timestamp][key] = point
        cohort: dict[str, list[MetricPoint]] = defaultdict(list)
        previous = None

        def snapshot() -> dict[str, MetricSeries]:
            """Freeze this contiguous run before starting another with possibly the same IDs."""
            return {k: MetricSeries(self.series[k].name, "Maximum", self.series[k].unit, tuple(ps))
                    for k, ps in cohort.items()}

        for stamp, members in sorted(buckets.items()):
            if previous is not None and cohort and (members.keys() != cohort.keys()
                                                    or stamp - previous != self.granularity):
                yield snapshot()
                cohort.clear()
            if len(members) >= 2:
                for key, point in members.items():
                    cohort[key].append(point)
            previous = stamp
        if cohort:
            yield snapshot()


def coverage_evidence(histories: tuple[RegionHistory, ...]) -> dict:
    """Expose coverage without leaking owner RIDs or treating an unknown count as zero."""
    return {"coverage_complete": bool(histories) and all(h.complete for h in histories),
            "partition_coverage": [h.evidence() for h in histories]}


class PartitionReader:
    """Bounded per-provider cache of identical reads; independent workers never share SDK state."""

    def __init__(self, client):
        self.client = client
        self.count = lru_cache(maxsize=16)(self._count)
        self.region = lru_cache(maxsize=8)(self._region)

    def _rows(self, rid, name, scope, window, top):
        """Return raw SDK rows; keep repeat IDs intact until scope and timestamps are reconciled."""
        response = self.client.query_resource(
            rid, metric_names=[name], aggregations=[MetricAggregationType.MAXIMUM],
            filter=scope, timespan=(window.start, window.end), granularity=window.granularity,
            max_results=top,
        )
        return [ts for metric in response.metrics for ts in metric.timeseries]

    def _count(self, rid, scope, window):
        """Use the same offer and region throughout the window, not DX-009's recent maximum."""
        # Count has no one-minute grain. For shorter evaluation windows use its native 5m grain.
        count_window = TimeWindow(window.start, window.end,
                                  max(window.granularity, timedelta(minutes=5)))
        rows = self._rows(rid, "PhysicalPartitionCount", scope, count_window, 2)
        if len(rows) != 1:
            return None, "count_missing_or_ambiguous"
        points = [p for p in rows[0].data if p.maximum is not None]
        counts = {p.maximum for p in points}
        if len(counts) != 1:
            return None, "count_changed" if counts else "count_missing_or_ambiguous"
        n = counts.pop()
        if not isfinite(n) or n < 1 or n != int(n):
            return None, "count_invalid"
        if not _covers_window({p.timestamp for p in points}, count_window):
            return None, "count_history_incomplete"
        return int(n), None

    def _region(self, rid: str, db: str, container: str | None, owner: str | None,
                region: str, window: TimeWindow, metric: str) -> RegionHistory:
        """Corroborate, recover and qualify one region without filling absent samples with zero."""
        scope = f"DatabaseName eq {quote(db)} and Region eq {quote(region)}"
        if owner:
            scope += f" and OfferOwnerRid eq {quote(owner)}"
        elif container:
            scope += f" and CollectionName eq {quote(container)}"
        else:
            return RegionHistory(region, None, 0, {}, ("shared_offer_identity_missing",), window.granularity)
        issues = []
        try:
            expected, issue = self.count(rid, scope, window)
        except READ_ERRORS as exc:
            expected, issue = None, _read_error("count", exc)
        if issue:
            issues.append(issue)
        top = min(SERIES_LIMIT, max(16, (expected or 0) + 1))
        dim = "PhysicalPartitionId"
        filt = f"{scope} and {dim} eq '*'"
        try:
            rows = self._rows(rid, metric, filt, window, top)
        except READ_ERRORS as exc:
            return RegionHistory(region, expected, 0, {}, (*issues, _read_error("split", exc)), window.granularity)
        series, conflicts, unknown = split_series(rows, metric, "Maximum", dim)
        capped = len(rows) >= top
        # One wider attempt for a potentially truncated response. Union rather than replace it.
        if top < SERIES_LIMIT and (capped or (rows and expected and len(series) < expected)):
            try:
                more = self._rows(rid, metric, filt, window, SERIES_LIMIT)
                capped = len(more) >= SERIES_LIMIT
                rows.extend(more)
                series, conflicts, unknown = split_series(rows, metric, "Maximum", dim)
            except READ_ERRORS as exc:
                issues.append(_read_error("wider_split", exc))
        # Known IDs with incomplete histories can be recovered without inventing missing IDs.
        gaps = [k for k, s in series.items() if not _covers_window(
            {p.timestamp for p in s.points}, window)]
        for key in sorted(gaps)[:TARGETED_LIMIT]:
            try:
                extra = self._rows(rid, metric, f"{scope} and {dim} eq {quote(key)}", window, 2)
            except READ_ERRORS as exc:
                issues.append(_read_error("targeted_split", exc))
                break
            if any(metadata(ts).get(dim.casefold()) != key for ts in extra):
                issues.append("unexpected_targeted_identity")
            rows.extend(ts for ts in extra if metadata(ts).get(dim.casefold()) == key)
        if gaps:
            series, conflicts, unknown = split_series(rows, metric, "Maximum", dim)
        observed = len(series) + len(conflicts)
        # Monitor may label the first intersecting bucket before an unaligned eval start.
        usable = {}
        for key, s in series.items():
            points = tuple(p for p in s.points if window.start - window.granularity
                           < p.timestamp < window.end)
            if points:
                usable[key] = MetricSeries(s.name, s.aggregation, s.unit, points)
        if conflicts:
            issues.append("conflicting_partition_samples")
        if unknown:
            issues.append("unidentified_series")
        if capped:
            issues.append("series_limit_reached")
        if observed != expected or len(usable) != observed:
            issues.append("partition_count_unverified")
        grids = {tuple(p.timestamp for p in s.points) for s in usable.values()}
        if len(grids) > 1 or any(not _covers_window(grid, window) for grid in grids):
            issues.append("partition_history_incomplete")
        return RegionHistory(region, expected, observed, usable, tuple(issues), window.granularity)


def _read_error(stage, exc):
    """Keep an unavailable read distinct from an empty successful response in report evidence."""
    if isinstance(exc, MonitorUnavailable):
        return f"{stage}_read_error:{exc}"
    return f"{stage}_read_error:{getattr(exc, 'status_code', None) or type(exc).__name__}"


def _covers_window(stamps, window):
    """Require contiguous grain-spaced buckets covering the requested interval, not just N IDs."""
    if not stamps:
        return False
    ordered = sorted(stamps)
    grain = window.granularity
    return (len(ordered) >= ceil((window.end - window.start) / grain)
            and window.start - grain < ordered[0] <= window.start
            and window.end - grain <= ordered[-1] < window.end
            and all(b - a == grain for a, b in zip(ordered, ordered[1:])))

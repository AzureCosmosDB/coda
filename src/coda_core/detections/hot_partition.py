"""DX-006: report co-observed physical partition skew separately from offer-level throttling.

A single hourly hot/cool contrast is an observation. A finding requires the same hot partition
in the same region in two consecutive completed hours. Only the matching hours' request counts
can promote it to High. Neither signal identifies a logical key or the source of a specific 429.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from math import isfinite

from azure.core.exceptions import AzureError

from coda_core.providers.arm import ThroughputOffer
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricSeries, TimeWindow
from coda_core.providers.partition_metrics import RegionHistory, coverage_evidence
from coda_core.providers.shared_offer import IncompletePool, PoolMembers, RequestCounts, request_series

PRODUCTION_WINDOW_DAYS = 7
HOUR = timedelta(hours=1)


def production_window(now: datetime | None = None) -> TimeWindow:
    """Keep the seven-day hourly lookback; there is no separate age floor."""
    end = now or datetime.now(timezone.utc)
    return TimeWindow(end - timedelta(days=PRODUCTION_WINDOW_DAYS), end, HOUR)


@dataclass(frozen=True)
class HotPartitionConfig:
    """Utilization gates apply to hourly maxima; impact gates apply to each witness hour."""

    saturation_pct: float = 90.0
    uniform_min_pct: float = 70.0
    throttle_rate_pct: float = 1.0
    min_total_requests: int = 1000


@dataclass(frozen=True)
class HotPartitionVerdict:
    """Only Medium and High are actionable; exact scope, measurements and times are in evidence."""

    root_cause: str
    severity: str
    recommended_action: str
    methodology: dict

    @property
    def is_hot_partition(self) -> bool:
        return self.root_cause == "hot_partition"

    def as_dict(self) -> dict:
        return {**asdict(self), "is_hot_partition": self.is_hot_partition}


@dataclass(frozen=True)
class _Contrast:
    """One same-region, same-timestamp Maximum comparison between identified physical partitions."""

    region: str
    start: datetime
    hot_id: str
    hot_pct: float
    cool_id: str
    cool_pct: float
    complete_hour: bool


def _counts(series: MetricSeries) -> dict[datetime, int | None]:
    """Never use a duplicate, absent, negative or fractional request count for escalation."""
    result = {}
    for p in series.points:
        v = p.value
        valid = isinstance(v, (int, float)) and not isinstance(v, bool) and isfinite(v) and v >= 0 and int(v) == v
        result[p.timestamp] = int(v) if valid and p.timestamp not in result else None
    return result


def classify(histories: tuple[RegionHistory, ...], window: TimeWindow,
             request_counts: tuple[MetricSeries, MetricSeries] | None, *,
             config: HotPartitionConfig | None = None, pressure_issue: str | None = None) -> HotPartitionVerdict:
    """Select the strongest, then latest, evidenced episode; never pool hours, regions or hot IDs."""
    cfg = config or HotPartitionConfig()
    evidence = coverage_evidence(histories)
    evidence.update(thresholds=asdict(cfg), observation_start=window.start.isoformat(),
                    observation_end=window.end.isoformat())
    totals, throttles = (_counts(s) for s in request_counts) if request_counts else ({}, {})

    def counts_at(stamp):
        if not window.start <= stamp < window.end:
            return None, None
        t, r = totals.get(stamp), throttles.get(stamp)
        if t is not None and r is not None and r > t:
            return None, None
        return t, r

    def material(stamp):
        t, r = counts_at(stamp)
        return t is not None and r is not None and t >= cfg.min_total_requests and 100*r >= cfg.throttle_rate_pct*t

    best: tuple[_Contrast, ...] = ()
    best_rank = None
    measured_429s = {stamp: r for stamp in throttles if (r := counts_at(stamp)[1]) is not None}
    evidence["window_observed_429s"] = sum(measured_429s.values()) if measured_429s else None
    if pressure_issue:
        evidence["throttling_unavailable"] = pressure_issue
    negative_causes = set()
    has_completed_hour = False
    for h in histories:
        if h.granularity != HOUR:
            evidence["coverage_complete"] = False
            continue
        buckets = defaultdict(dict)
        for key, series in h.series.items():
            for point in series.points:
                v, stamp = point.value, point.timestamp
                if not (window.start - HOUR < stamp < window.end):
                    continue
                if v is None or not isfinite(v) or not 0 <= v <= 100:
                    evidence["coverage_complete"] = False
                    continue
                buckets[stamp][key] = v
        previous = {}
        for stamp, readings in sorted(buckets.items()):
            complete = window.start <= stamp and stamp + HOUR <= window.end
            has_completed_hour |= complete
            coolest = min(readings, key=lambda key: (readings[key], key))
            hot = {key: v for key, v in readings.items() if v >= cfg.saturation_pct}
            if h.complete and complete:
                negative_causes.add("single_partition" if h.expected == 1 else
                                    "uniform_saturation" if hot else "not_saturated")
            current = {}
            if hot and readings[coolest] < cfg.uniform_min_pct:
                for key, value in hot.items():
                    here = _Contrast(h.region, stamp, key, value, coolest, readings[coolest], complete)
                    prior = previous.get(key)
                    pair = (prior, here) if (complete and prior and prior.complete_hour
                                             and prior.start + HOUR == stamp) else (here,)
                    level = 0 if len(pair) == 1 else 2 if all(material(w.start) for w in pair) else 1
                    rank = (level, stamp, value, h.region, key)
                    if best_rank is None or rank > best_rank:
                        best_rank, best = rank, pair
                    current[key] = here
            previous = current

    if not best:
        if not has_completed_hour or not evidence["coverage_complete"] or not negative_causes:
            evidence["abstained"] = "incomplete_partition_coverage"
            cause = "insufficient_data"
        else:
            cause = next(iter(negative_causes)) if len(negative_causes) == 1 else "no_regional_skew"
        return HotPartitionVerdict(cause, "none", "", evidence)

    hours = []
    for w in best:
        t, r = counts_at(w.start)
        hours.append({**asdict(w), "start": max(w.start, window.start).isoformat(), "end": min(w.start+HOUR, window.end).isoformat(),
                      "total_requests": t, "throttled_requests": r,
                      "throttle_rate_pct": 100*r/t if t and r is not None else None})
    counts_known = all(h["total_requests"] is not None and h["throttled_requests"] is not None for h in hours)
    t = sum(h["total_requests"] for h in hours) if counts_known else None
    r = sum(h["throttled_requests"] for h in hours) if counts_known else None
    witness_stamps = {w.start for w in best}
    evidence.update(witness_region=best[-1].region, physical_partition_id=best[-1].hot_id,
                    comparable_buckets=len(hours), intervals=hours, total_requests=t, throttled_requests=r,
                    throttle_rate_pct=100*r/t if t else None,
                    other_observed_429s=sum(r for stamp, r in measured_429s.items() if stamp not in witness_stamps))
    if not counts_known:
        evidence["throttling_unavailable"] = pressure_issue or "Missing or inconsistent counts for a witness hour"
    if len(best) == 1:
        evidence["abstained"] = "skew_observed_once"
        return HotPartitionVerdict("skew_observed", "none", "", evidence)
    return HotPartitionVerdict("hot_partition", "high" if all(material(w.start) for w in best) else "medium",
        "Investigate the workload and key distribution in the observed region. "
        "These metrics cannot identify a logical partition key or tell which partition returned a 429.",
        evidence)


def detect_hot_partition(
    metrics: AzureMonitorMetricsProvider, account_resource_id: str, database: str, container: str | None,
    offer: ThroughputOffer, window: TimeWindow, *, config: HotPartitionConfig | None = None,
    resource_created_at: datetime | None = None, regions: tuple[str | None, ...] = (),
    pool_members: PoolMembers | None = None, read_counts: RequestCounts | None = None,
    as_of: datetime | None = None,
) -> HotPartitionVerdict:
    """Read the comparable hourly series once. A failed count read cannot erase observed skew."""
    end = min(window.end, as_of or datetime.now(timezone.utc))
    start = max(window.start, resource_created_at) if resource_created_at else window.start
    if start >= end:
        return HotPartitionVerdict("insufficient_data", "none", "", {"abstained": "no_elapsed_window"})
    # Keep mature-offer reads identical to DX-005. For a clipped first hour, query from
    # creation; a returned intersecting bucket may be described but cannot count as a full hour.
    window = TimeWindow(start, end, HOUR)
    histories = metrics.partition_histories(account_resource_id, "NormalizedRUConsumption", window,
        database=database, container=container, owner_rid=offer.owner_rid, regions=regions)
    issue = None
    try:
        counts = (read_counts(window) if read_counts else
                  request_series(metrics, account_resource_id, window, database, container, pool_members))
    except (AzureError, IncompletePool, ValueError) as exc:
        counts = None
        issue = f"Offer request counts read failed: {getattr(exc, 'status_code', None) or type(exc).__name__}"
    return classify(histories, window, counts, config=config, pressure_issue=issue)

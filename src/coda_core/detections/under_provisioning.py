"""DX-005: observe server-side 429s immediately; verify broad pressure hour by hour."""

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
from coda_core.providers.shared_offer import IncompletePool, PoolMembers, RequestCounts, request_series, verified_members

PRODUCTION_WINDOW_DAYS = 7
HOUR = timedelta(hours=1)


def _floor(stamp: datetime) -> datetime:
    """Use UTC clock hours so a partial first or last hour cannot qualify."""
    return stamp.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def production_window(now: datetime | None = None) -> TimeWindow:
    """Include the current partial hour for observation, in addition to the completed hours."""
    end = now or datetime.now(timezone.utc)
    return TimeWindow(_floor(end) - timedelta(days=PRODUCTION_WINDOW_DAYS), end, HOUR)


@dataclass(frozen=True)
class UnderProvisioningConfig:
    """Existing inclusive pressure and impact cutoffs, applied independently to each hour."""

    throttle_rate_pct: float = 1.0
    saturation_pct: float = 90.0
    uniform_min_pct: float = 70.0
    min_total_requests: float = 1000.0
    severity_high_pct: float = 20.0
    severity_med_pct: float = 5.0


@dataclass(frozen=True)
class UnderProvisioningVerdict:
    """Capacity advice is present only for a pair of qualifying hours on this offer."""

    root_cause: str
    severity: str
    recommended_action: str
    methodology: dict

    @property
    def is_under_provisioned(self) -> bool:
        return self.root_cause == "global_under_provisioning"

    def as_dict(self) -> dict:
        return {**asdict(self), "is_under_provisioned": self.is_under_provisioned}


def _counts(series: MetricSeries, window: TimeWindow) -> dict:
    """Keep only integer, nonnegative counts; a repeated label is ambiguous."""
    values = {}
    for p in series.points:
        if (not window.start - HOUR < p.timestamp < window.end
                or (p.timestamp < window.start and window.start == _floor(window.start))):
            continue
        stamp = max(window.start, p.timestamp)
        n = p.value
        values[stamp] = (int(n) if stamp not in values and type(n) in (float, int)
                         and isfinite(n) and n >= 0 and n == int(n) else None)
    return values


def _regional_hours(h: RegionHistory) -> dict:
    """Compare identified partitions to that hour's count, not the week's union of IDs."""
    hours = defaultdict(list)
    for series in h.series.values():
        for p in series.points:
            hours[p.timestamp].append(p.value)
    # A gap/change elsewhere need not invalidate this hour; identity ambiguity or truncation can.
    unsafe = set(h.issues) - {"count_changed", "count_history_incomplete",
                              "partition_count_unverified", "partition_history_incomplete"}
    result = {}
    mixed_hours = {_floor(stamp) for stamp in hours if stamp != _floor(stamp)}
    for stamp, readings in hours.items():
        if not all(type(v) in (int, float) and isfinite(v) and 0 <= v <= 100 for v in readings):
            continue
        expected = h.counts_by_time.get(stamp, h.expected if h.complete else None)
        result[stamp] = {"region": h.region, "count": len(readings), "expected": expected,
                         "complete": not unsafe and len(readings) == expected and h.granularity == HOUR
                                     and stamp not in mixed_hours,
                         "minimum_pct": min(readings), "maximum_pct": max(readings)}
    return result


def _offer_counts(metrics, rid, database, container, pool, read_counts, span) -> tuple[dict, dict]:
    """Sum only complete same-hour shared membership; gaps elsewhere cannot erase a measured pair."""
    if container is not None:
        counts = read_counts(span) if read_counts else request_series(metrics, rid, span, database, container, pool)
        return tuple(_counts(series, span) for series in counts)
    members = verified_members(pool)
    if not members:
        raise IncompletePool("No verified shared members")
    combined = None
    for member in members:
        counts = request_series(metrics, rid, span, database, member, None)
        total, throttled = (_counts(series, span) for series in counts)
        for stamp in total.keys() & throttled.keys():
            if total[stamp] is not None and throttled[stamp] is not None and throttled[stamp] > total[stamp]:
                total[stamp] = throttled[stamp] = None
        if combined is None:
            combined = (total, throttled)
        else:
            for accumulated, current in zip(combined, (total, throttled)):
                for stamp in accumulated.keys() | current.keys():
                    a, b = accumulated.get(stamp), current.get(stamp)
                    accumulated[stamp] = None if a is None or b is None else a+b
    return combined


def detect_under_provisioning(
    metrics: AzureMonitorMetricsProvider, account_resource_id: str, database: str, container: str | None,
    offer: ThroughputOffer, window: TimeWindow, *, config: UnderProvisioningConfig | None = None,
    resource_created_at: datetime | None = None, regions: tuple[str | None, ...] = (),
    pool_members: PoolMembers | None = None, read_counts: RequestCounts | None = None,
    as_of: datetime | None = None,
) -> UnderProvisioningVerdict:
    """Read offer counts and match each completed hour to a complete same-hour regional split."""
    cfg = config or UnderProvisioningConfig()
    start = max(window.start, resource_created_at) if resource_created_at else window.start
    end = min(window.end, as_of or datetime.now(timezone.utc))
    evidence = {"thresholds": asdict(cfg), "observation_start": start.isoformat(),
                "observation_end": end.isoformat()}

    def verdict(cause, *, issue=None, severity="none", action=""):
        if issue:
            evidence["abstained"] = issue
        return UnderProvisioningVerdict(cause, severity, action, evidence)

    if start >= end:
        return verdict("insufficient_data", issue="no_elapsed_window")
    first = start if start == _floor(start) else _floor(start) + HOUR
    last = _floor(end)
    totals, throttles = {}, {}
    # Query a clipped birth/window boundary separately; its labels must not shift later hours.
    bounds = sorted({start, end, *([first] if start < first < end else [])})
    for a, b in zip(bounds, bounds[1:]):
        span = TimeWindow(a, b, HOUR)
        try:
            t, r = _offer_counts(metrics, account_resource_id, database, container, pool_members, read_counts, span)
        except (AzureError, IncompletePool, ValueError) as exc:
            evidence["count_issue"] = getattr(exc, "reason", type(exc).__name__)
            continue
        totals.update(t)
        throttles.update(r)
    matched = {s: (t, r) for s, t in totals.items() if t is not None
               and (r := throttles.get(s)) is not None and r <= t}
    measured = {s: r for s, r in throttles.items() if r is not None
                and (totals.get(s) is None or r <= totals[s])}
    if measured:
        evidence["throttled_requests"] = sum(measured.values())
        if measured.keys() == matched.keys():
            t = sum(v[0] for v in matched.values())
            evidence.update(total_requests=t, throttle_rate_pct=100*sum(measured.values())/t if t else None)
    if len(matched) < len(totals.keys() | throttles.keys()) or not matched:
        issue = ("inconsistent_request_counts" if any(totals.get(s) is not None and r is not None
                 and r > totals[s] for s, r in throttles.items()) else "missing_request_counts")
        evidence.setdefault("count_issue", issue)
    mixed_hours = {_floor(s) for s in totals.keys() | throttles.keys() if s != _floor(s)}
    material = {s: pair for s, pair in matched.items() if s == _floor(s) and first <= s < last and s not in mixed_hours
                and pair[0] >= cfg.min_total_requests and 100*pair[1] >= cfg.throttle_rate_pct*pair[0]}
    if not material:
        if not matched or evidence.get("count_issue"):
            return verdict("insufficient_data", issue=evidence["count_issue"])
        if not any(measured.values()):
            return verdict("not_throttling")
        if not any(t >= cfg.min_total_requests for t, _ in matched.values()):
            return verdict("insufficient_data", issue="too_few_requests")
        if any(100*r >= cfg.throttle_rate_pct*t for t, r in matched.values() if t and r):
            return verdict("pressure_observed")
        return verdict("below_throttle_threshold")

    try:
        histories = metrics.partition_histories(account_resource_id, "NormalizedRUConsumption",
            TimeWindow(first, last, HOUR), database=database, container=container,
            owner_rid=offer.owner_rid, regions=regions)
    except (AzureError, ValueError) as exc:
        evidence["partition_issue"] = type(exc).__name__
        return verdict("insufficient_data", issue="incomplete_partition_coverage")
    evidence.update(coverage_evidence(histories))
    scopes_match = (bool(regions) and all(regions) and len(set(regions)) == len(regions)
                    and sorted(h.region for h in histories) == sorted(regions))
    regional = [_regional_hours(h) for h in histories]
    qualifying, causes = {}, set()
    best = None
    for stamp, (t, r) in sorted(material.items()):
        rows = [data[stamp] for data in regional if stamp in data]
        skew = next((row for row in rows if row["maximum_pct"] >= cfg.saturation_pct
                     and row["minimum_pct"] < cfg.uniform_min_pct), None)
        if skew:
            evidence["witness_region"] = skew["region"]
            causes.add("skew_suspected")
        elif not scopes_match or len(rows) != len(regions) or not all(row["complete"] for row in rows):
            causes.add("insufficient_data")
        elif not all(row["maximum_pct"] >= cfg.saturation_pct for row in rows):
            causes.add("regional_saturation" if any(row["maximum_pct"] >= cfg.saturation_pct
                       for row in rows) else "throttling_without_saturation")
        else:
            qualifying[stamp] = {"start": stamp.isoformat(), "end": (stamp+HOUR).isoformat(),
                                 "total_requests": t, "throttled_requests": r, "throttle_rate_pct": 100*r/t,
                                 "regions": rows}
            if stamp-HOUR in qualifying:
                pair = [qualifying[stamp-HOUR], qualifying[stamp]]
                rate = min(hour["throttle_rate_pct"] for hour in pair)
                if best is None or rate >= best[0]:
                    best = rate, pair
    if best:
        rate, evidence["intervals"] = best
        severity = "high" if rate >= cfg.severity_high_pct else "medium" if rate >= cfg.severity_med_pct else "low"
        knob = "the autoscale maximum" if offer.mode == "autoscale" else "provisioned throughput"
        return verdict("global_under_provisioning", severity=severity,
                       action=f"Consider raising {knob} for the observed load if it is representative.")
    if qualifying:
        return verdict("pressure_observed")
    if "insufficient_data" in causes:
        return verdict("insufficient_data", issue="incomplete_partition_coverage")
    return verdict(next(c for c in ("skew_suspected", "regional_saturation",
                                     "throttling_without_saturation") if c in causes))

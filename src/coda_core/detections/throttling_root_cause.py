"""DX-021: reconcile account-level 429s with operation counts in the exact same time bucket."""

from __future__ import annotations

from dataclasses import dataclass

from azure.core.exceptions import AzureError

from coda_core.detections import request_intervals as hours
from coda_core.detections.request_intervals import production_window as production_window
from coda_core.providers.base import TimeWindow
from coda_core.providers.monitor_retry import MonitorUnavailable


@dataclass(frozen=True)
class OperationBreakdown:
    """Expose operation counts and shares only after all attributed 429s reconcile."""

    attribution: str
    counts: dict
    shares_pct: dict


def detect_throttling_root_cause(total_requests: int, total_throttled: int,
                                 op_throttled_counts: dict) -> OperationBreakdown:
    """A share of all 429s describes recipients, not the throttle rate within an operation."""
    ops = op_throttled_counts or {}
    if (not total_throttled or not 0 < total_throttled <= total_requests
            or any(not isinstance(k, str) or not k.strip() or isinstance(n, bool)
                   or not isinstance(n, (int, float)) or not float(n).is_integer() or n < 0
                   for k, n in ops.items())
            or sum(ops.values()) != total_throttled):
        return OperationBreakdown("unavailable", {}, {})
    counts = {op: int(n) for op, n in sorted(ops.items()) if n}
    return OperationBreakdown("reconciled", counts, {k: 100*n/total_throttled for k, n in counts.items()})


def observe(metrics, resource_id: str, window: TimeWindow) -> dict:
    """Join independently scoped status and filtered operation reads by exact timestamp, never range total."""
    window = hours.hourly_window(window)
    status = hours.split_hours(metrics.get_metric_split(
        resource_id, "TotalRequests", window, split_dimension="StatusCode", aggregation="Count"), window)
    affected = [(stamp, sum(cs.values()), cs["429"]) for stamp, cs in status.items() if cs.get("429")]
    # A quiet control needs observed traffic: zero throttles on zero requests is not an exercised workload.
    ops, evidence = {}, {"measured_intervals": len(status), "affected_intervals": [],
                         "measured_requests": sum(sum(cs.values()) for cs in status.values())}
    if not affected:
        return evidence
    try:
        ops = hours.split_hours(metrics.get_metric_split(
            resource_id, "TotalRequests", window, split_dimension="OperationType",
            dimension_filter={"StatusCode": "429"}, aggregation="Count"), window)
    except (AzureError, ValueError) as exc:
        evidence["operation_error"] = type(exc).__name__
        if isinstance(exc, MonitorUnavailable):
            evidence.update(http_status=exc.status_code, retry_after_seconds=exc.retry_after_seconds)
    for stamp, total, throttled in affected:
        v = detect_throttling_root_cause(total, throttled, ops.get(stamp, {}))
        row = {**hours.interval(stamp, window), "total_requests": total, "total_throttled": throttled,
               "throttle_rate_pct": 100 * throttled / total, "attribution": v.attribution}
        if v.attribution == "reconciled":
            row.update(op_throttled_counts=v.counts, op_share_of_429s_pct=v.shares_pct)
        evidence["affected_intervals"].append(row)
    return evidence

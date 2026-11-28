"""DX-020: show server response counts by status; grade only same-hour 5xx service responses."""

from __future__ import annotations

from coda_core.detections import request_intervals as hours
from coda_core.detections.request_intervals import production_window as production_window
from coda_core.providers.base import TimeWindow

MIN_TOTAL_REQUESTS = 1000
HARD_ERROR_RATE_PCT = 1.0
SEVERITY_MEDIUM_PCT = 5.0
SEVERITY_HIGH_PCT = 10.0


def detect_error_patterns(counts: dict[str, int], *, completed: bool) -> dict:
    """Keep 4xx descriptive and 429 denominator-only; do not infer client failures or a cause."""
    if any(not str(code).isascii() or not str(code).isdigit() or
           not 100 <= int(code) <= 599 for code in counts):
        raise ValueError("Unrecognized HTTP status in TotalRequests")
    total = sum(counts.values())
    errors = {str(c): n for c, n in sorted(counts.items()) if int(c) >= 400 and int(c) != 429 and n}
    service = sum(n for c, n in errors.items() if int(c) >= 500)
    rate = 100 * service / total if total else 0
    severity = "none"
    if completed and total >= MIN_TOTAL_REQUESTS and rate >= HARD_ERROR_RATE_PCT:
        severity = "high" if rate >= SEVERITY_HIGH_PCT else "medium" if rate >= SEVERITY_MEDIUM_PCT else "low"
    return {"total_requests": total, "status_code_counts": errors,
            "status_rates_pct": {c: 100 * n / total for c, n in errors.items()},
            "service_error_requests": service, "service_error_rate_pct": rate, "severity": severity}


def observe(metrics, resource_id: str, window: TimeWindow) -> dict:
    """Read account-only StatusCode counts once, retaining observations from every affected interval."""
    window = hours.hourly_window(window)
    by_code = metrics.get_metric_split(resource_id, "TotalRequests", window,
                                       split_dimension="StatusCode", aggregation="Count")
    by_hour = hours.split_hours(by_code, window)
    affected = []
    for stamp, counts in by_hour.items():
        bounds = hours.interval(stamp, window)
        row = detect_error_patterns(counts, completed=bounds["completed_hour"])
        if row["status_code_counts"]:
            affected.append({**bounds, **row})
    return {"affected_intervals": affected, "measured_intervals": len(by_hour),
            "min_total_requests": MIN_TOTAL_REQUESTS, "service_error_rate_pct_threshold": HARD_ERROR_RATE_PCT}

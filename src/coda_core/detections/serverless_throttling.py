"""DX-018: classify observed serverless 429s by UTC hour; separate incident from mode review."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from coda_core.detections import request_intervals as hours
from coda_core.detections.request_intervals import production_window as production_window
from coda_core.providers.base import DataProvider, TimeWindow


@dataclass(frozen=True)
class ServerlessThrottleConfig:
    """Keep incident volume and severity gates separate from the persistence required for advice."""

    throttle_rate_pct: float = 1.0
    min_total_requests: float = 1000.0
    severity_high_pct: float = 20.0
    severity_med_pct: float = 5.0


def classify(rate: float | None, total: int | None, completed: bool,
             cfg: ServerlessThrottleConfig) -> str:
    """Grade only a material rate in a sufficiently busy completed hour, using unrounded counts."""
    if not completed or rate is None or total is None or total < cfg.min_total_requests or rate < cfg.throttle_rate_pct:
        return "none"
    return "high" if rate >= cfg.severity_high_pct else "medium" if rate >= cfg.severity_med_pct else "low"


def detect_serverless_throttling(metrics: DataProvider, account_resource_id: str, database: str,
                                container: str, window: TimeWindow, *,
                                config: ServerlessThrottleConfig | None = None) -> dict:
    """Pair same-container hourly counts and retain every observed incident, including small bursts."""
    cfg = config or ServerlessThrottleConfig()
    window = hours.hourly_window(window)
    if not all(name and name != "*" for name in (database, container)):
        raise ValueError("An exact database and container are required for serverless request counts")
    scope = {"DatabaseName": database, "CollectionName": container}

    def counts(filters: dict) -> dict:
        """Read Count, not Total; never join the numerator to a different hour's volume."""
        series = metrics.get_metric(account_resource_id, "TotalRequests", window,
                                    aggregation="Count", dimension_filter=filters)
        return hours.samples(series, window)

    totals, throttles = counts(scope), counts({**scope, "StatusCode": "429"})
    affected, material = [], set()
    for stamp, n in sorted(throttles.items()):
        if not n:
            continue
        total = totals.get(stamp)
        rate = 100 * n / total if total and total >= n else None
        row = hours.interval(stamp, window)
        severity = classify(rate, total, row["completed_hour"], cfg)
        affected.append({**row, "total_requests": total, "total_throttled": n,
                         "throttle_rate_pct": rate, "severity": severity})
        if severity != "none":
            material.add(stamp)
    return {"affected_intervals": affected, "measured_pairs": len(totals.keys() & throttles.keys()),
            "material_hours": len(material), "material_utc_days": len({t.date() for t in material}),
            "capacity_mode_review": (any(t - timedelta(hours=1) in material for t in material)
                                     or len({t.date() for t in material}) >= 3)}

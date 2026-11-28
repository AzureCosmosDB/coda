"""DX-017: describe measured container data growth without forecasting a partition limit."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from coda_core.detections import request_intervals as hours
from coda_core.providers.base import DataProvider, TimeWindow

GIB = 1024**3


@dataclass(frozen=True)
class StorageGrowthConfig:
    """Require consecutive fully measured growing UTC days before prompting a retention review."""

    consecutive_growth_days: int = 3


def production_window(now: datetime | None = None) -> TimeWindow:
    """Request 30 days of hourly container-level measurements, not inferred past growth."""
    return hours.production_window(now, days=30)


def detect_storage_growth(metrics: DataProvider, resource_id: str, database: str, container: str,
                          window: TimeWindow, *, config: StorageGrowthConfig | None = None) -> dict:
    """Compare hourly container DataUsage maxima, keeping missing and measured zero distinct."""
    if not all(name and name != "*" for name in (database, container)):
        raise ValueError("An exact database and container are required for storage measurements")
    cfg = config or StorageGrowthConfig()
    window = hours.hourly_window(window)
    series = metrics.get_metric(resource_id, "DataUsage", window, aggregation="Maximum",
                                dimension_filter={"DatabaseName": database, "CollectionName": container})
    values = hours.samples(series, window, counts=False)
    evidence = {"source": "container DataUsage (Maximum)", "measured_hours": len(values)}
    if not values:
        return evidence
    first, last = min(values), max(values)
    evidence.update(first_sample_utc=first.isoformat(), first_bytes=values[first],
                    last_sample_utc=last.isoformat(), last_bytes=values[last],
                    change_bytes=values[last] - values[first] if first != last else None)
    dates = sorted({t.date() for t in values})
    streak, qualified = [], []
    for day in dates:
        midnight = first.replace(year=day.year, month=day.month, day=day.day,
                                 hour=0, minute=0, second=0, microsecond=0)
        grid = [midnight + h * hours.HOUR for h in range(24)]
        if (all(t in values and hours.complete(t, window) for t in grid)
                and values[grid[-1]] > values[grid[0]]):
            if streak and day - streak[-1] != timedelta(days=1):
                streak = []
            streak.append(day)
            if len(streak) >= cfg.consecutive_growth_days:
                qualified = streak[-cfg.consecutive_growth_days:]
        else:
            streak = []
    evidence["retention_review_days"] = [day.isoformat() for day in qualified]
    return evidence

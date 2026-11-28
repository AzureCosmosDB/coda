"""Time and count boundaries shared by hourly Cosmos request diagnostics.

Monitor labels buckets by their start. Keep measurements separate rather than summing
unrelated hours; a partial boundary bucket can be described but never graded.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import isfinite

from coda_core.providers.base import MetricSeries, TimeWindow

HOUR = timedelta(hours=1)


def production_window(now: datetime | None = None, *, days: int = 7) -> TimeWindow:
    """Start on a UTC hour boundary and include the latest observations through the run anchor."""
    end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = end.replace(minute=0, second=0, microsecond=0) - timedelta(days=days)
    return TimeWindow(start, end, HOUR)


def hourly_window(window: TimeWindow) -> TimeWindow:
    """Preserve pinned bounds, requesting actual hourly buckets even in evaluation mode."""
    return TimeWindow(window.start, window.end, HOUR)


def complete(stamp: datetime, window: TimeWindow) -> bool:
    """A completed UTC hour is fully contained in the requested interval."""
    utc = stamp.astimezone(timezone.utc)
    return (not any((utc.minute, utc.second, utc.microsecond)) and
            window.start <= stamp and stamp + HOUR <= window.end)


def samples(series: MetricSeries, window: TimeWindow, *, counts: bool = True) -> dict:
    """Accept only unambiguous in-window nonnegative measurements, never treating gaps as zero."""
    values, seen = {}, set()
    for point in series.points:
        if point.timestamp.utcoffset() is None:
            raise ValueError(f"{series.name} measurement has no time zone")
        stamp = point.timestamp.astimezone(timezone.utc)
        if not window.start <= stamp < window.end:
            continue
        n = point.value
        if stamp in seen:
            raise ValueError(f"duplicate {series.name} measurement at {stamp.isoformat()}")
        seen.add(stamp)
        if n is None:
            continue
        if (isinstance(n, bool) or not isfinite(n) or n < 0 or (counts and int(n) != n)):
            raise ValueError(f"invalid {series.name} measurement at {stamp.isoformat()}")
        values[stamp] = int(n) if counts else n
    return values


def split_hours(groups: dict[str, MetricSeries], window: TimeWindow) -> dict:
    """Pivot exact split series to one map per timestamp; never move counts across hours."""
    rows = {}
    for key, series in groups.items():
        for stamp, value in samples(series, window).items():
            rows.setdefault(stamp, {})[key] = value
    return dict(sorted(rows.items()))


def interval(stamp: datetime, window: TimeWindow) -> dict:
    """Return unambiguous machine-readable bounds and the independent severity eligibility bit."""
    return {"start_utc": stamp.isoformat(), "end_utc": min(stamp + HOUR, window.end).isoformat(),
            "completed_hour": complete(stamp, window)}

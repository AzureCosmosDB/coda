"""Time and identity boundaries shared by the four throughput advice detectors (ADR-0086)."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import isfinite

from coda_core.providers.base import MetricSeries, TimeWindow

HOUR = timedelta(hours=1)
WEEK = 168
MONTH = 720


@dataclass(frozen=True)
class ThroughputHistory:
    """Keep actual observations separate from the recent consecutive hours usable for advice."""

    observed: MetricSeries
    evaluated: MetricSeries
    consecutive: int
    end: datetime
    unverified_leading_zeros: int

    def evidence(self) -> dict:
        """Report how much was measured and which interval was actually used."""
        points = self.evaluated.points
        return {
            "observed_samples": len(self.observed.points),
            "latest_consecutive_hours": self.consecutive,
            "unverified_leading_zero_samples": self.unverified_leading_zeros,
            "coverage_end_exclusive": self.end.isoformat(),
            "evaluated_samples": len(points),
            "first_evaluated_sample": points[0].timestamp.isoformat() if points else None,
            "last_evaluated_sample": points[-1].timestamp.isoformat() if points else None,
        }


def throughput_history(series: MetricSeries, window: TimeWindow,
                       created_at: datetime | None = None, *, existed_by: datetime | None = None,
                       exclude_unverified_zero_padding: bool = False) -> ThroughputHistory:
    """Select the latest complete month, else latest complete week, else observations only.

    No interpolating gaps, accepting an open hour, counting minute samples as hours, or
    inheriting another resource's history when a container name has been reused.
    """
    end = window.end.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = max(window.start, end - MONTH * HOUR, created_at or window.start)
    samples = {}
    seen = set()
    for point in series.points:
        stamp, value = point.timestamp, point.value
        if not start <= stamp < window.end:
            continue
        if stamp in seen or value is None or not isfinite(value) or not 0 <= value <= 100:
            samples.pop(stamp, None)
        else:
            samples[stamp] = point
        seen.add(stamp)
    # Monitor can pad normalized utilization with zeros before a resource exists. A same-resource
    # ARM lower bound or observed positive utilization distinguishes later measured zeros from
    # that padding. Scaled totals already require an independent positive partition count.
    since = start
    if exclude_unverified_zero_padding:
        positive = min((t for t, p in samples.items() if p.value > 0), default=end)
        since = min(positive, created_at or existed_by or end)
    unverified = sum(t < since for t in samples)
    count = 0
    if window.granularity == HOUR:
        # A sub-hour sample next to an on-grid label is not an hourly maximum certificate.
        mixed_grain = {t - (t - end) % HOUR for t in seen if (t - end) % HOUR}
        while (count < MONTH and (stamp := end - (count + 1) * HOUR) in samples
               and stamp >= since and stamp not in mixed_grain):
            count += 1
    observed = tuple(samples[s] for s in sorted(samples))
    size = MONTH if count == MONTH else WEEK if count >= WEEK else 0
    evaluated = tuple(samples[end - i * HOUR] for i in range(size, 0, -1)) if size else observed
    return ThroughputHistory(
        MetricSeries(series.name, series.aggregation, series.unit, observed),
        MetricSeries(series.name, series.aggregation, series.unit, evaluated), count, end, unverified)

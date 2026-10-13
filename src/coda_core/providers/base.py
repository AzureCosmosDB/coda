"""Core value types and the DataProvider contract.

The single most important design decision lives here: a detection's lookback is an
**absolute** :class:`TimeWindow` (start, end, granularity), never a hardcoded
relative offset like ``ago(7d)``.

Why this matters (see the project plan + gap analysis):
  * The detection-validation generator produces a *bounded burst* of real load,
    recording the exact ``[start, end]`` window it ran in. Tests then PIN
    detections to that window and replay them for as long as the telemetry is
    retained (~93 days for Azure Monitor Metrics; configurable up to 2 years for
    Log Analytics). That removes any need to maintain load indefinitely.
  * Telemetry cannot be backfilled into the past — it only exists for the real
    time spans during which load actually ran. An absolute window is the only
    honest way to point detections at that real data.

Every provider method therefore takes a :class:`TimeWindow` explicitly.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class TimeWindow:
    """An absolute, timezone-aware analysis window.

    Attributes:
        start: Inclusive start (must be timezone-aware UTC).
        end: Exclusive end (must be timezone-aware UTC).
        granularity: Aggregation bucket size (e.g. 1 minute, 1 hour). Providers
            map this onto the backing store's native granularity.
    """

    start: datetime
    end: datetime
    granularity: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        for name, value in (("start", self.start), ("end", self.end)):
            if value.tzinfo is None:
                raise ValueError(f"TimeWindow.{name} must be timezone-aware (UTC).")
        if self.end <= self.start:
            raise ValueError("TimeWindow.end must be after TimeWindow.start.")

    @classmethod
    def trailing(
        cls, duration: timedelta, *, granularity: timedelta = timedelta(minutes=5)
    ) -> "TimeWindow":
        """Convenience: a window of ``duration`` ending now (UTC).

        Use for ad-hoc/live queries. Fixtures and tests should construct explicit
        ``[start, end]`` windows instead, pinned to a recorded generation run.
        """
        now = datetime.now(timezone.utc)
        return cls(start=now - duration, end=now, granularity=granularity)


@dataclass(frozen=True)
class MetricPoint:
    """A single aggregated metric sample at ``timestamp``."""

    timestamp: datetime
    value: float | None


@dataclass(frozen=True)
class MetricSeries:
    """A named, ordered series of aggregated samples over a window.

    Attributes:
        name: The source metric name (provider-native, e.g. "NormalizedRUConsumption").
        aggregation: Which aggregation the points represent (e.g. "Average", "Maximum").
        unit: Provider-reported unit, if any.
        points: Time-ordered samples covering the requested window.
    """

    name: str
    aggregation: str
    unit: str | None
    points: tuple[MetricPoint, ...]

    def values(self) -> list[float]:
        """Non-null values, in time order. Convenience for findings math."""
        return [p.value for p in self.points if p.value is not None]


class DataProvider(abc.ABC):
    """Abstract source of customer observability data.

    Detection logic depends on this interface only. Concrete implementations read
    Azure Monitor Metrics, Log Analytics, or ARM. Auth is injected by the caller
    (a credential), so local ``az login`` and service on-behalf-of are both
    supported without changing detection code.
    """

    @abc.abstractmethod
    def get_metric(
        self,
        resource_id: str,
        metric_name: str,
        window: TimeWindow,
        *,
        aggregation: str = "Average",
        dimension_filter: dict[str, str] | None = None,
    ) -> MetricSeries:
        """Return one metric as an aggregated time series over ``window``.

        ``dimension_filter`` optionally scopes to specific dimension values (e.g. a
        single container via ``{"CollectionName": "..."}``).
        """
        raise NotImplementedError

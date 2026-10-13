"""Data-sufficiency framework (ADR-0008): a uniform "do we have enough to judge?" check.

Detections declare a :class:`DataRequirement`; a shared evaluator returns an
:class:`Insufficiency` (uniform abstain) when telemetry is too thin, instead of a verdict.

Distinct from preflight (``coda_core.preflight``): preflight asks *can we read the source at
all?* (permissions/precondition); this asks *is there enough data over the detection's window?*

Note the floor is **span-based**, not a raw point count: a genuinely over-provisioned
low-usage container emits *few but time-spread* points, so requiring N points would wrongly
abstain on exactly the containers we want to flag. We require the observed telemetry to **span**
at least ``window_floor`` (plus a small min-points sanity floor for stable percentiles).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from coda_core.providers.base import MetricSeries


@dataclass(frozen=True)
class DataRequirement:
    """What a detection needs before it will render a verdict.

    window_floor: the telemetry must **span** at least this long (first to last observed point);
        a brand-new container with only hours of history is abstained, not judged.
    min_points: a small floor on non-null samples to avoid noisy percentiles.
    """

    window_floor: timedelta
    min_points: int = 24


@dataclass(frozen=True)
class Insufficiency:
    reason: str  # "no_data" | "too_few_points" | "span_too_short"
    detail: str
    fix_hint: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def evaluate_series(series: MetricSeries, requirement: DataRequirement) -> Insufficiency | None:
    """Return an :class:`Insufficiency` if the series can't support a verdict, else ``None``."""
    points = [p for p in series.points if p.value is not None]
    if not points:
        return Insufficiency(
            "no_data", "no telemetry in window",
            "Confirm the resource has activity and metrics/diagnostics are flowing.",
        )
    if len(points) < requirement.min_points:
        return Insufficiency(
            "too_few_points", f"{len(points)} points < {requirement.min_points} required",
            "Not enough samples yet for a confident verdict.",
        )
    return None


def evaluate_age(
    created_at: datetime, reference_time: datetime, window_floor: timedelta
) -> Insufficiency | None:
    """Abstain if a resource is younger than ``window_floor`` (too new to judge).

    Needed because Azure Monitor pads the requested window with zeros even before a resource
    existed (so metric span is *not* a usable age signal) — resource age must come from the
    control plane (ARM/Activity Log).
    """
    if reference_time - created_at < window_floor:
        return Insufficiency(
            "too_new",
            f"resource age {reference_time - created_at} < required {window_floor}",
            "Resource is too new for a confident verdict; revisit after it accrues history.",
        )
    return None

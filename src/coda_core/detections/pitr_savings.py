"""Fail-closed storage snapshot selection and DX-019 retail-price savings math.

Azure Monitor emits ``DataUsageV2`` as one byte-valued series per logical container and region.
DX-019 intentionally reads one configured reference region and one timestamp: summing time buckets
or replicated-region copies would overstate storage. ARM inventory is the completeness authority.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

DECIMAL_BYTES_PER_GB = 1_000_000_000
MAX_STORAGE_SNAPSHOT_AGE = timedelta(hours=6)
MAX_FUTURE_SKEW = timedelta(minutes=5)


class PitrSavingsUnavailable(ValueError):
    """The storage or price evidence is not complete enough to assert dollar savings."""


@dataclass(frozen=True)
class DataUsageSample:
    """One raw ``DataUsageV2`` series value at one timestamp in one configured region."""

    timestamp: datetime
    database: str
    container: str
    region: str
    bytes_used: float


@dataclass(frozen=True)
class StorageSnapshot:
    """A complete, fresh, single-timestamp logical-storage observation."""

    timestamp: datetime
    reference_region: str
    logical_containers: int
    total_bytes: float

    @property
    def decimal_gb(self) -> float:
        """Convert bytes to decimal GB because the Retail Prices billing unit is exactly ``1 GB``."""
        return self.total_bytes / DECIMAL_BYTES_PER_GB


def select_complete_storage_snapshot(
    samples: tuple[DataUsageSample, ...],
    expected_containers: tuple[tuple[str, str], ...],
    reference_region: str,
    now: datetime,
    *,
    max_age: timedelta = MAX_STORAGE_SNAPSHOT_AGE,
) -> StorageSnapshot:
    """Select the newest fresh timestamp containing every ARM container exactly once.

    A timestamp is complete only when its series identities exactly equal ARM inventory. Duplicate
    identities, extra containers, negative/non-finite values, region mismatches, future timestamps,
    and stale snapshots fail closed. A numeric zero is retained as observed data, unlike a missing
    series, which makes the timestamp incomplete.
    """
    if now.tzinfo is None:
        raise PitrSavingsUnavailable("storage_snapshot_now_not_timezone_aware")
    expected = tuple(expected_containers)
    expected_set = set(expected)
    if len(expected_set) != len(expected):
        raise PitrSavingsUnavailable("arm_inventory_contains_duplicate_containers")
    if not expected_set:
        raise PitrSavingsUnavailable("arm_inventory_contains_no_logical_containers")
    if not reference_region:
        raise PitrSavingsUnavailable("reference_region_missing")

    by_timestamp: dict[datetime, list[DataUsageSample]] = {}
    for sample in samples:
        if sample.timestamp.tzinfo is None:
            raise PitrSavingsUnavailable("storage_timestamp_not_timezone_aware")
        if sample.region.casefold() != reference_region.casefold():
            raise PitrSavingsUnavailable("storage_series_outside_reference_region")
        if not math.isfinite(sample.bytes_used) or sample.bytes_used < 0:
            raise PitrSavingsUnavailable("storage_value_invalid")
        by_timestamp.setdefault(sample.timestamp, []).append(sample)

    complete: StorageSnapshot | None = None
    for timestamp in sorted(by_timestamp, reverse=True):
        rows = by_timestamp[timestamp]
        identities = [(row.database, row.container) for row in rows]
        if len(set(identities)) != len(identities):
            continue
        if set(identities) != expected_set:
            continue
        complete = StorageSnapshot(
            timestamp=timestamp,
            reference_region=reference_region,
            logical_containers=len(expected),
            total_bytes=sum(row.bytes_used for row in rows),
        )
        break

    if complete is None:
        raise PitrSavingsUnavailable("no_complete_storage_timestamp")
    now_utc = now.astimezone(timezone.utc)
    timestamp_utc = complete.timestamp.astimezone(timezone.utc)
    if timestamp_utc > now_utc + MAX_FUTURE_SKEW:
        raise PitrSavingsUnavailable("storage_timestamp_in_future")
    if now_utc - timestamp_utc > max_age:
        raise PitrSavingsUnavailable("storage_snapshot_stale")
    return complete


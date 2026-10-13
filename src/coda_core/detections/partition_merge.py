"""DX-009: Partition merge candidate (over-partitioned container).

A container's provisioned RU/s is divided evenly across its physical partitions, and each physical
partition supports up to ~10,000 RU/s and ~50 GiB. If a container has **more physical partitions than
its throughput and storage need** — typically a leftover from having once been scaled to a high RU/s
(or large) and then scaled back down — each partition gets a thin slice of RU/s. That makes
**per-partition throttling** possible even while the container as a whole looks under-utilised, and it
is wasteful. Merging the partitions back down consolidates the RU/s.

Signal (Azure Monitor + ARM, no Log Analytics): the **actual** physical partition count
(``PhysicalPartitionCount``) vs the count actually **needed** = max(provisioned RU/s ÷ 10,000,
storage ÷ 50 GiB, 1). When actual exceeds needed, the container is over-partitioned. Merge is a
platform operation (Portal/CLI), so there is no Agent Kit code remediation. Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow

RU_PER_PARTITION = 10_000.0
BYTES_PER_PARTITION = 50 * 1024**3
# Partition count is slow-moving state; a short recent window at the metric's 5-minute grain is enough.
WINDOW_HOURS = 6
GRANULARITY = timedelta(minutes=5)


def recent_window(now: datetime | None = None) -> TimeWindow:
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(hours=WINDOW_HOURS), anchor, GRANULARITY)


def needed_partitions(provisioned_ru: float, storage_bytes: float) -> int:
    """The smallest physical-partition count that satisfies the RU/s and storage needs."""
    import math
    for_ru = math.ceil(provisioned_ru / RU_PER_PARTITION) if provisioned_ru > 0 else 1
    for_storage = math.ceil(storage_bytes / BYTES_PER_PARTITION) if storage_bytes > 0 else 1
    return max(for_ru, for_storage, 1)


@dataclass(frozen=True)
class PartitionMergeVerdict:
    is_over_partitioned: bool
    actual_partitions: int
    needed_partitions: int
    provisioned_ru: float
    storage_bytes: float
    ru_per_partition: float       # provisioned_ru / actual_partitions (the thin slice)
    severity: str                 # medium | low | none
    # over_partitioned | right_sized | single_partition | insufficient_data
    root_cause: str
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def classify(actual: int, provisioned_ru: float, storage_bytes: float) -> PartitionMergeVerdict:
    needed = needed_partitions(provisioned_ru, storage_bytes)
    ru_slice = (provisioned_ru / actual) if actual > 0 else provisioned_ru
    base = dict(actual_partitions=actual, needed_partitions=needed, provisioned_ru=provisioned_ru,
                storage_bytes=storage_bytes, ru_per_partition=round(ru_slice, 1),
                methodology={"ru_per_partition_limit": RU_PER_PARTITION,
                             "gib_per_partition_limit": BYTES_PER_PARTITION // 1024**3,
                             "needed_for_ru_storage": needed})

    if actual <= 0:
        return PartitionMergeVerdict(is_over_partitioned=False, severity="none",
                                     root_cause="insufficient_data", recommended_action="", **base)
    if actual == 1:
        return PartitionMergeVerdict(is_over_partitioned=False, severity="none",
                                     root_cause="single_partition", recommended_action="", **base)
    if actual <= needed:
        return PartitionMergeVerdict(is_over_partitioned=False, severity="none",
                                     root_cause="right_sized", recommended_action="", **base)

    # Over-partitioned. Severity reflects how thin the per-partition RU slice is relative to the need.
    severity = "medium" if actual >= 2 * needed else "low"
    action = (
        f"This container has {actual} physical partitions but its {provisioned_ru:.0f} RU/s and "
        f"{storage_bytes / 1024**3:.1f} GiB only need {needed}. Each partition therefore gets just "
        f"~{ru_slice:.0f} RU/s, so a single hot partition can throttle while the container looks "
        f"under-utilised. This usually follows scaling RU/s down (or deleting data) after a high-"
        f"throughput/large period. Merge the partitions (Azure Portal / CLI) to consolidate the RU/s."
    )
    return PartitionMergeVerdict(is_over_partitioned=True, severity=severity,
                                 root_cause="over_partitioned", recommended_action=action, **base)


def detect_partition_merge(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    provisioned_ru: float,
    window: TimeWindow,
) -> PartitionMergeVerdict:
    """End-to-end DX-009 for one container."""
    scope = {"DatabaseName": database, "CollectionName": container}
    pcount = metrics.get_metric(account_resource_id, "PhysicalPartitionCount", window,
                                aggregation="Maximum", dimension_filter=scope)
    storage = metrics.get_metric(account_resource_id, "DataUsage", window,
                                 aggregation="Maximum", dimension_filter=scope)
    pvals = pcount.values()
    if not pvals:
        return classify(0, provisioned_ru, 0.0)
    actual = int(max(pvals))
    storage_bytes = max(storage.values()) if storage.values() else 0.0
    return classify(actual, provisioned_ru, storage_bytes)

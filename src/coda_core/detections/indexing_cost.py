"""DX-024: compare measured index and data footprints; size alone cannot identify unused paths."""

from __future__ import annotations

from azure.core.exceptions import AzureError
from coda_core.providers.indexing_batch import IncompleteBatch, InvalidIndexingInventory

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.base import DataProvider, TimeWindow

# Storage is slow-moving state; a short recent window at the metric's 5-minute grain is enough (DX-009).
WINDOW_HOURS = 6
GRANULARITY = timedelta(minutes=5)

# The default policy's only exclusion is the system ``_etag`` path, in either quoting style. Other
# ``_etag`` forms (e.g. ``/_etag/*``) are user-authored and count as exclusions (extension parity).
DEFAULT_EXCLUDED_PATHS = frozenset({'/_etag/?', '/"_etag"/?'})


@dataclass(frozen=True)
class IndexingCostConfig:
    review_ratio: float = 0.3   # strict >; a review prompt, not severity


def production_window(now: datetime | None = None) -> TimeWindow:
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(hours=WINDOW_HOURS), anchor, GRANULARITY)


def user_excluded_paths(excluded_paths: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    """Excluded paths the customer authored (everything except the default ``_etag`` exclusion)."""
    return tuple(p for p in (excluded_paths or ()) if p not in DEFAULT_EXCLUDED_PATHS)


@dataclass(frozen=True)
class IndexingCostVerdict:
    is_risk: bool
    severity: str                  # medium | low | none
    # high_index_ratio | normal_ratio | indexing_disabled | insufficient_data
    root_cause: str
    index_bytes: float | None
    data_bytes: float | None
    ratio: float | None
    user_excluded_path_count: int
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _finite_nonneg(value: float | None) -> bool:
    return value is not None and math.isfinite(value) and value >= 0


def classify(
    index_bytes: float | None,
    data_bytes: float | None,
    *,
    indexing_mode: str | None = "consistent",
    excluded_paths: tuple[str, ...] | list[str] | None = (),
    config: IndexingCostConfig = IndexingCostConfig(),
) -> IndexingCostVerdict:
    """Classify one container's indexing footprint. Pure (no I/O)."""
    user_paths = user_excluded_paths(excluded_paths)
    methodology = {
        "review_ratio_threshold": config.review_ratio,
        "indexing_mode": indexing_mode,
        "user_excluded_path_count": len(user_paths),
        "user_excluded_paths": list(user_paths),
        "source": "Azure Monitor IndexUsage/DataUsage (latest) + ARM indexingPolicy",
    }
    base = dict(index_bytes=index_bytes, data_bytes=data_bytes,
                user_excluded_path_count=len(user_paths), methodology=methodology)

    if (indexing_mode or "").lower() == "none":
        return IndexingCostVerdict(is_risk=False, severity="none", root_cause="indexing_disabled",
                                   ratio=None, recommended_action="", **base)
    if not _finite_nonneg(index_bytes) or not _finite_nonneg(data_bytes) or not data_bytes:
        methodology["abstained"] = "no positive DataUsage or no IndexUsage telemetry"
        return IndexingCostVerdict(is_risk=False, severity="none", root_cause="insufficient_data",
                                   ratio=None, recommended_action="", **base)

    ratio = index_bytes / data_bytes
    methodology["ratio"] = round(ratio, 4)
    if ratio <= config.review_ratio:
        return IndexingCostVerdict(is_risk=False, severity="none", root_cause="normal_ratio",
                                   ratio=ratio, recommended_action="", **base)

    methodology["visible_observation"] = True
    action = (
        "Review which indexed paths representative queries use to filter or sort, including infrequent jobs. "
        "Test query behavior and write RU before excluding a path. Index size alone does not establish waste."
    )
    return IndexingCostVerdict(is_risk=True, severity="none", root_cause="high_index_ratio",
                               ratio=ratio, recommended_action=action, **base)


def detect_indexing_cost(
    metrics: DataProvider,
    account_resource_id: str,
    database: str,
    container: str,
    window: TimeWindow,
    *,
    indexing_mode: str | None,
    excluded_paths: tuple[str, ...] | list[str] | None,
    config: IndexingCostConfig = IndexingCostConfig(),
) -> IndexingCostVerdict:
    """End-to-end DX-024 for one container (latest index/data bytes, extension parity)."""
    scope = {"DatabaseName": database, "CollectionName": container}
    try:
        index = metrics.get_metric(account_resource_id, "IndexUsage", window,
                                   aggregation="Maximum", dimension_filter=scope)
        data = metrics.get_metric(account_resource_id, "DataUsage", window,
                                  aggregation="Maximum", dimension_filter=scope)
    except (IncompleteBatch, AzureError) as exc:
        if isinstance(exc, InvalidIndexingInventory) or (indexing_mode or "").lower() != "none":
            raise
        result = classify(None, None, indexing_mode=indexing_mode, excluded_paths=excluded_paths, config=config)
        result.methodology["storage_read_issue"] = type(exc).__name__
        return result
    index_sizes = {p.timestamp: p.value for p in index.points if p.value is not None}
    data_sizes = {p.timestamp: p.value for p in data.points if p.value is not None}
    latest = max(index_sizes.keys() & data_sizes.keys(), default=None)
    result = classify(index_sizes.get(latest), data_sizes.get(latest), indexing_mode=indexing_mode,
                      excluded_paths=excluded_paths, config=config)
    if latest is not None:
        result.methodology["sample_at"] = latest.isoformat()
    return result

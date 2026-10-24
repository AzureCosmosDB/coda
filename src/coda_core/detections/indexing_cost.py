"""DX-024: Indexing cost risk (index storage large relative to data).

Every indexed path costs write RU on every insert/replace and adds index storage. The default
NoSQL indexing policy indexes **every** path, so containers whose queries touch only a few
properties pay for index entries they never use. A large index-to-data storage ratio is the
observable footprint of that over-indexing.

Ported from the Azure Cosmos DB VS Code extension's ``IndexingCostRisk`` advisory (TS source
``IndexingCostRiskDetector.ts``) with two deliberate, fleet-grounded differences (ADR-0069):

* **Never abstain on user exclusions.** The extension stays silent whenever the policy excludes
  any path besides the default ``_etag``. A container that excluded one small path can still index
  everything else, so CODA keeps flagging it and reports the exclusion count as evidence instead.
* **Banded severity.** Low when index > 30% of data (the extension's cutoff); Medium when the index
  is *larger than the data itself* (> 100%). Fleet probe 2026-10-22 (20% sample, consistent-indexing
  containers): 27.5% exceed 0.3 and 3.3% exceed 1.0 (``docs/evidence/dx024-indexing-ratio.md``).

Signal (Azure Monitor + ARM, no Log Analytics): latest ``IndexUsage`` and ``DataUsage`` bytes for the
container, plus its ARM indexing policy (mode + excluded paths). Read-only / diagnose-only: the
remediation (``index-exclude-unused``) is a policy change the customer applies.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow

# Storage is slow-moving state; a short recent window at the metric's 5-minute grain is enough (DX-009).
WINDOW_HOURS = 6
GRANULARITY = timedelta(minutes=5)

# The default policy's only exclusion is the system ``_etag`` path, in either quoting style. Other
# ``_etag`` forms (e.g. ``/_etag/*``) are user-authored and count as exclusions (extension parity).
DEFAULT_EXCLUDED_PATHS = frozenset({'/_etag/?', '/"_etag"/?'})


@dataclass(frozen=True)
class IndexingCostConfig:
    low_ratio: float = 0.3      # strict >, extension parity
    medium_ratio: float = 1.0   # strict >: index larger than the data it indexes


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
        "low_ratio_threshold": config.low_ratio,
        "medium_ratio_threshold": config.medium_ratio,
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
    if ratio <= config.low_ratio:
        return IndexingCostVerdict(is_risk=False, severity="none", root_cause="normal_ratio",
                                   ratio=ratio, recommended_action="", **base)

    severity = "medium" if ratio > config.medium_ratio else "low"
    tuned = (f" The policy already excludes {len(user_paths)} path(s); review whether more unused "
             f"paths can be excluded." if user_paths else
             " The policy excludes no paths beyond the default, so every property is indexed.")
    action = (
        f"Index storage is {ratio:.0%} of data storage ({index_bytes / 1024**3:.2f} GiB index vs "
        f"{data_bytes / 1024**3:.2f} GiB data). Every indexed path adds write RU to each insert and "
        f"replace and grows index storage.{tuned} Exclude paths your queries never filter or sort on "
        f"(or switch to an include-list policy) to cut write RU and storage."
    )
    return IndexingCostVerdict(is_risk=True, severity=severity, root_cause="high_index_ratio",
                               ratio=ratio, recommended_action=action, **base)


def _latest(series) -> float | None:
    """Latest non-null sample; the newest grain is often still unpopulated (null) at query time."""
    values = series.values()
    return values[-1] if values else None


def detect_indexing_cost(
    metrics: AzureMonitorMetricsProvider,
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
    index = metrics.get_metric(account_resource_id, "IndexUsage", window,
                               aggregation="Maximum", dimension_filter=scope)
    data = metrics.get_metric(account_resource_id, "DataUsage", window,
                              aggregation="Maximum", dimension_filter=scope)
    return classify(_latest(index), _latest(data), indexing_mode=indexing_mode,
                    excluded_paths=excluded_paths, config=config)

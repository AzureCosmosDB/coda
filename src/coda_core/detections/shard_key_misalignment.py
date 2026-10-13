"""DX-007: Shard-key misalignment (structural escalation of DX-002).

DX-002 flags individual query *shapes* that fan out. DX-007 is the container-level **structural**
verdict: when the **dominant** share of query executions fans out across multiple partitions, the
problem is the **partition key itself** (the data model), not individual queries — so the remediation
is to **re-key** the container (migration-class), not tweak queries.

Signal: identical to DX-002 — ``CDBQueryRuntimeStatistics`` fan-out (``dcount(PartitionKeyRangeId)`` per
``CorrelatedActivityId``), now **cost-gated** (ADR-0033): a shape counts toward the fan-out share only
if it also averages >= the RU gate, so DX-007 fires when *expensive* fan-out dominates — the
fleet-grounded refinement that promotes it to ``validated`` (pure fan-out over-flagged ~64-77% of
multi-partition collections; the cost gate isolates the ~3-7% real tail —
``docs/evidence/dx002-dx007-fanout-validation.md``). DX-007 reuses
:func:`cross_partition_query.detect_cross_partition_queries` and applies a higher, structural
threshold; it therefore requires **both** the ``QueryRuntimeStatistics`` and ``DataPlaneRequests``
categories. There is **no** independent "is the partition key in the filter" signal: query text is
anonymized (``p1``/``p2``) and ``AggregatedQueryRuntimeStatistics5M`` does not exist, so misalignment is
**inferred from expensive-fan-out dominance**, not read from field names (ADR-0024).

Correlation: when DX-007 fires it **supersedes DX-002** on the same container in the rollup — re-keying
subsumes per-query fixes. Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

from coda_core.detections import cross_partition_query as cpq
from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import LogAnalyticsProvider


def production_window(now: datetime | None = None) -> TimeWindow:
    return cpq.production_window(now)


@dataclass(frozen=True)
class ShardKeyConfig:
    structural_pct: float = 60.0   # >= this share of executions fanning out => the KEY is misaligned
    min_partitions: int = 2        # needs multiple physical partitions for a key-level problem
    severity_high_pct: float = 80.0


@dataclass(frozen=True)
class ShardKeyVerdict:
    is_misaligned: bool
    # shard_key_misaligned | not_misaligned | log_analytics_unavailable | insufficient_data
    root_cause: str
    cross_partition_pct: float
    container_partitions: int
    worst_shape: str | None
    severity: str  # high | medium | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _from_cpq(v: cpq.CrossPartitionVerdict, root_cause: str, cfg: ShardKeyConfig, **kw) -> ShardKeyVerdict:
    method = dict(v.methodology)
    method["dx007_structural_pct"] = cfg.structural_pct
    method["dx007_min_partitions"] = cfg.min_partitions
    base = dict(
        is_misaligned=False, root_cause=root_cause, cross_partition_pct=v.cross_partition_pct,
        container_partitions=v.container_partitions, worst_shape=v.worst_shape, severity="none",
        recommended_action="", methodology=method,
    )
    base.update(kw)
    return ShardKeyVerdict(**base)


def detect_shard_key_misalignment(
    la: LogAnalyticsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    window: TimeWindow,
    *,
    config: ShardKeyConfig | None = None,
    cpq_config: cpq.CrossPartitionConfig | None = None,
) -> ShardKeyVerdict:
    """End-to-end DX-007 for one container, escalating DX-002's fan-out signal."""
    cfg = config or ShardKeyConfig()
    v = cpq.detect_cross_partition_queries(
        la, account_resource_id, database, container, window, config=cpq_config
    )

    # Propagate the non-judgable cases (abstain) so the report's LA guardrail still fires.
    if v.root_cause in ("log_analytics_unavailable", "insufficient_data"):
        return _from_cpq(v, v.root_cause, cfg)

    misaligned = (
        v.cross_partition_pct >= cfg.structural_pct and v.container_partitions >= cfg.min_partitions
    )
    if not misaligned:
        # Aligned, single-partition, or only a per-query problem (DX-002's domain) — not structural.
        return _from_cpq(v, "not_misaligned", cfg)

    severity = "high" if v.cross_partition_pct >= cfg.severity_high_pct else "medium"
    action = (
        f"{v.cross_partition_pct:.0f}% of this container's query executions fan out across "
        f"~{v.container_partitions} physical partitions — the **partition key is structurally "
        f"misaligned** with the workload (this is the data model, not a single bad query). Re-key the "
        f"container so the dominant query filter becomes the partition key. This is migration-class: "
        f"create a new container with the corrected key, backfill the data, and cut over. Per-query "
        f"fixes (DX-002) cannot resolve a fundamentally mismatched key, and the cost grows as the "
        f"container adds partitions."
    )
    return _from_cpq(
        v, "shard_key_misaligned", cfg, is_misaligned=True, severity=severity,
        recommended_action=action,
    )

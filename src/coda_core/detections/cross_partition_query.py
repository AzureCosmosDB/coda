"""DX-002: Cross-partition query fan-out.

A query that doesn't filter on the container's partition key fans out across **every** physical
partition, multiplying RU cost and latency — common, expensive, and fixable in app code (add the
partition key to the filter, denormalize, or rework to a single-partition pattern).

Signal & data source: **Log Analytics** ``CDBQueryRuntimeStatistics``. Each row is one query operation
against a single ``PartitionKeyRangeId``; a cross-partition query therefore appears as several rows
sharing one ``CorrelatedActivityId`` (the logical query). So the **fan-out of a logical query** is
``dcount(PartitionKeyRangeId)`` grouped by ``CorrelatedActivityId``, and a query *shape*
(``QueryText``) that averages > 1 partition is fanning out. The container's physical partition count is
estimated as the widest fan-out observed.

There is **no RU column** in ``CDBQueryRuntimeStatistics``, so the RU of each fan-out query is recovered
by joining ``CDBDataPlaneRequests`` (``RequestCharge``) on ``ActivityId``. A shape is flagged only when
it both fans out **and** is expensive (avg RU >= a fleet-grounded gate) — pure fan-out over-flags
(ADR-0033; ``docs/evidence/dx002-dx007-fanout-validation.md``). This detector therefore requires **both**
the ``QueryRuntimeStatistics`` and ``DataPlaneRequests`` diagnostic categories; if either is missing it
abstains (the capability layer emits the category-precise "enable X" message). Single-partition
containers cannot fan out and are not flagged. The logged ``QueryText`` is **anonymized** (identifiers →
``p1``/``p2``, literals → ``str1``, parameters → ``@param1``), so we surface the query *shape*, not the
customer's literal query — the remediation is structural (add the partition key to the filter) regardless.

Graceful degradation: if the customer has not enabled diagnostic settings exporting ``CDB*`` logs, this
detection **abstains** with an "enable Log Analytics" message. Read-only / diagnose-only.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import LogAnalyticsProvider


def production_window(now: datetime | None = None) -> TimeWindow:
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=1), anchor, timedelta(hours=1))


def query_shape_kql(database: str, container: str) -> str:
    """KQL for the top query fan-out shapes for one container, **with per-query RU cost**.

    Fan-out alone over-flags (a fleet sample found ~64-77% of multi-partition, query-active
    collections at >=60% fan-out — most of them cheap, well-indexed cross-partition scans that are
    not a problem; see ``docs/evidence/dx002-dx007-fanout-validation.md``). ``CDBQueryRuntimeStatistics``
    has **no cost column**, so we join ``CDBDataPlaneRequests`` (which carries ``RequestCharge``) on
    ``ActivityId`` to recover each logical query's RU: a cross-partition query is one
    ``CorrelatedActivityId`` spanning several ``ActivityId`` (one per physical partition), and its RU
    is the sum of those requests' ``RequestCharge``. The classifier then flags a shape only when it
    both fans out **and** is expensive (avg RU >= the fleet-grounded gate) — the selective ~3-7% tail.

    The runner reuses this exact string when it primes the per-run LA cache from a batched account
    query, so parallelization does not change detector semantics or cache keys.
    """
    db = database.replace("'", "")
    coll = container.replace("'", "")
    return (
        "CDBQueryRuntimeStatistics "
        f"| where DatabaseName == '{db}' and CollectionName == '{coll}' "
        "| project ActivityId, CorrelatedActivityId, QueryText, PartitionKeyRangeId "
        "| join kind=leftouter ("
        "CDBDataPlaneRequests "
        f"| where DatabaseName == '{db}' and CollectionName == '{coll}' "
        "| summarize ru = sum(RequestCharge) by ActivityId"
        ") on ActivityId "
        "| summarize partitionsHit = dcount(PartitionKeyRangeId), queryRU = sum(ru) "
        "by CorrelatedActivityId, QueryText "
        "| summarize executions = count(), avgFanout = avg(partitionsHit), "
        "maxFanout = max(partitionsHit), avgRU = avg(queryRU) by QueryText "
        "| top 200 by executions desc"
    )


def clean_query_text(raw: str) -> str:
    """Render a ``CDBQueryRuntimeStatistics`` ``QueryText`` value for display.

    The service logs the query as a JSON envelope ``{"query": "...", "parameters": [...]}`` and the
    SQL is **anonymized**: identifiers become ``p1``/``p2``, string literals become ``str1``, and
    parameters become ``@param1``. We extract the ``query`` field and collapse whitespace so the
    surfaced text shows the query *shape* (the customer's literal field names/values are not present
    in telemetry). Falls back to the raw value if it is not the expected envelope.
    """
    text = raw
    try:
        env = json.loads(raw)
        if isinstance(env, dict) and env.get("query"):
            text = str(env["query"])
    except (ValueError, TypeError):
        pass
    return " ".join(text.split())


@dataclass(frozen=True)
class QueryShape:
    """One query shape (by ``QueryText``) over the window."""

    text: str
    executions: int
    avg_fanout: float
    max_fanout: int
    avg_ru: float = 0.0              # avg RU of the logical query (from the CDBDataPlaneRequests join)


@dataclass(frozen=True)
class CrossPartitionConfig:
    min_queries: int = 50            # below this, too little query traffic to judge
    cross_fanout_threshold: float = 1.5  # a shape averaging >= this many partitions is cross-partition
    min_ru: float = 10.0             # a fan-out shape must ALSO average >= this RU to count as a problem
                                     # (fleet p90 of avg query RU ~= 10; grounded — ADR-0033)
    high_pct: float = 30.0           # >= this share of executions (expensive-fanout) -> high
    med_pct: float = 10.0            # >= this -> medium


@dataclass(frozen=True)
class CrossPartitionVerdict:
    is_cross_partition: bool
    # cross_partition | mostly_single_partition | single_partition_container | insufficient_data |
    # log_analytics_unavailable
    root_cause: str
    total_queries: int
    cross_partition_pct: float
    container_partitions: int        # estimated physical partition count (widest fan-out)
    worst_shape: str | None
    worst_shape_fanout: float
    severity: str  # high | medium | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _abstain(root_cause: str, detail: str) -> CrossPartitionVerdict:
    method = {"abstained": detail}
    if root_cause == "log_analytics_unavailable":
        method["la_unavailable"] = True
    return CrossPartitionVerdict(
        is_cross_partition=False, root_cause=root_cause, total_queries=0, cross_partition_pct=0.0,
        container_partitions=0, worst_shape=None, worst_shape_fanout=0.0, severity="none",
        recommended_action="", methodology=method,
    )


def classify(
    shapes: list[QueryShape], config: CrossPartitionConfig | None = None
) -> CrossPartitionVerdict:
    """Map per-shape query fan-out to a cross-partition verdict (pure)."""
    cfg = config or CrossPartitionConfig()
    total = sum(s.executions for s in shapes)
    container_partitions = max((s.max_fanout for s in shapes), default=0)
    cross_shapes = [
        s for s in shapes
        if s.avg_fanout >= cfg.cross_fanout_threshold and s.avg_ru >= cfg.min_ru
    ]
    cross_exec = sum(s.executions for s in cross_shapes)
    cross_pct = (100.0 * cross_exec / total) if total else 0.0
    worst = max(cross_shapes, key=lambda s: s.executions, default=None)

    def verdict(**kw) -> CrossPartitionVerdict:
        base = dict(
            is_cross_partition=False, root_cause="mostly_single_partition", total_queries=total,
            cross_partition_pct=round(cross_pct, 1), container_partitions=container_partitions,
            worst_shape=None, worst_shape_fanout=0.0, severity="none", recommended_action="",
            methodology={"thresholds": {"min_queries": cfg.min_queries,
                                        "cross_fanout_threshold": cfg.cross_fanout_threshold,
                                        "min_ru": cfg.min_ru,
                                        "high_pct": cfg.high_pct, "med_pct": cfg.med_pct},
                         "cross_partition_shapes": len(cross_shapes),
                         "note": "Query shapes are grouped by raw QueryText; literal values in a query "
                                 "produce distinct shapes (no server-side parameterisation)."},
        )
        base.update(kw)
        return CrossPartitionVerdict(**base)

    if total < cfg.min_queries:
        return verdict(root_cause="insufficient_data")
    if container_partitions <= 1:
        return verdict(root_cause="single_partition_container")  # cannot fan out
    if cross_pct < cfg.med_pct or worst is None:
        return verdict(root_cause="mostly_single_partition")

    severity = "high" if cross_pct >= cfg.high_pct else "medium"
    short = clean_query_text(worst.text)
    if len(short) > 200:
        short = short[:200] + "…"
    action = (
        f"{cross_pct:.0f}% of query executions fan out across partitions (the container has "
        f"~{container_partitions} physical partitions). The most frequent offender averages "
        f"{worst.avg_fanout:.1f} partitions and ~{worst.avg_ru:.0f} RU per run. Anonymized shape: "
        f"`{short}`. When the query can "
        f"carry the partition key, add the container's partition key to the filter (or a composite "
        f"index) so it targets one logical partition. For queries that inherently filter on a "
        f"different key (a global secondary access pattern), serve them from a global secondary index "
        f"— a service-managed Cosmos DB index on that key whose data Cosmos keeps in sync "
        f"automatically — rather than a manually maintained denormalized copy; denormalizing into a "
        f"change-feed-synced second container remains an option if a global secondary index does not "
        f"fit. Cross-partition fan-out multiplies RU and latency and does not scale as the container "
        f"grows."
    )
    return verdict(
        is_cross_partition=True, root_cause="cross_partition", severity=severity,
        worst_shape=short, worst_shape_fanout=round(worst.avg_fanout, 1),
        recommended_action=action,
    )


def detect_cross_partition_queries(
    la: LogAnalyticsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    window: TimeWindow,
    *,
    config: CrossPartitionConfig | None = None,
) -> CrossPartitionVerdict:
    """End-to-end DX-002 for one container.

    Capability availability (is ``CDBQueryRuntimeStatistics`` configured?) is gated upstream by the
    pipeline's capability layer, which abstains with a category-precise "enable X" message. Here we
    just query and, if the table is empty for this container, abstain ``insufficient_data`` — the
    honest "diagnostics are on, but there is no query telemetry to judge" answer.
    """
    span = (window.start, window.end)
    kql = query_shape_kql(database, container)
    try:
        rows = la.query_resource(account_resource_id, kql, span)
    except Exception as exc:  # noqa: BLE001 - degrade gracefully
        return _abstain("log_analytics_unavailable", f"Log Analytics query failed: {exc}")
    shapes = [
        QueryShape(
            text=r.get("QueryText") or "",
            executions=int(r.get("executions") or 0),
            avg_fanout=float(r.get("avgFanout") or 0.0),
            max_fanout=int(r.get("maxFanout") or 0),
            avg_ru=float(r.get("avgRU") or 0.0),
        )
        for r in rows if r.get("QueryText")
    ]
    if not shapes:
        return _abstain("insufficient_data", "No query telemetry for this container.")
    return classify(shapes, config)

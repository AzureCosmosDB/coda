"""DX-007: separate repeated all-query fan-out from a mixed workload's design-review prompt."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite

from coda_core.detections.cross_partition_query import MIXED_SPAN_NS, clean_query_text, production_window, query_shape_kql
from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import LogAnalyticsProvider

__all__ = ["ShardKeyConfig", "detect_shard_key_misalignment", "production_window"]


@dataclass(frozen=True)
class ShardKeyConfig:
    """Evidence required for the High exception, independent of query rate and cost."""

    min_start_hours: int = 3
    min_elapsed_hours: int = 4


@dataclass(frozen=True)
class ShardKeyVerdict:
    """Only `rekey` is a graded finding; observations remain visible without counting twice."""

    kind: str
    summary: str
    action: str
    evidence: dict


def _cost(row: dict) -> float | None:
    """Only call a sum a total when every fan-out activity has a usable charge."""
    ru = row["observedRU"]
    if row["missingCharges"] != 0 or ru is None or not isfinite(ru) or ru < 0:
        return None
    return float(ru)


def _stamp(value) -> str | None:
    """Use a JSON-safe timestamp for both SDK datetimes and recorded fixture rows."""
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def detect_shard_key_misalignment(
    la: LogAnalyticsProvider, account_resource_id: str, database: str, container: str,
    window: TimeWindow, *, history_issues: list[str], config: ShardKeyConfig | None = None,
) -> ShardKeyVerdict:
    """Read totals computed before top-shape limits; never infer every query from examples."""
    cfg = config or ShardKeyConfig()
    try:
        rows = la.query_resource(account_resource_id, query_shape_kql(database, container, window),
                                 (window.start, window.end))
    except Exception as exc:  # noqa: BLE001 - report the failed read, not an aligned key
        return ShardKeyVerdict("incomplete", f"Log Analytics query failed: {exc}", "",
                               {"abstained": "query_failed", "error": str(exc)})
    totals = [r for r in rows if r.get("recordKind") == "total"]
    if len(totals) != 1:
        reason = "No query telemetry" if not rows else "No unique complete execution summary"
        return ShardKeyVerdict("incomplete", f"{reason} for this container.", "", {"abstained": reason})
    row = totals[0]
    fan, single, unknown = (row[k] for k in ("fanExecutions", "singleExecutions", "unknownGroups"))
    observed_hours = (window.end - window.start).total_seconds() / 3600
    evidence = dict(fanout_executions=fan, single_partition_executions=single,
                    unclassifiable_groups=unknown, occupied_start_hours=row["occupiedHours"],
                    first_fanout_start=_stamp(row["firstFan"]), last_fanout_start=_stamp(row["lastFan"]),
                    total_fanout_ru=_cost(row), observation_start=window.start.isoformat(),
                    observation_end=window.end.isoformat(), history_issues=history_issues)
    if unknown:
        evidence["abstained"] = "unclassifiable_queries"
    prefix = f"{fan:,} fan-out and {single:,} single-partition logical queries observed"
    if (fan and not single and not unknown and not history_issues and observed_hours == 24
            and row["occupiedHours"] >= cfg.min_start_hours and row["spanNs"] is not None
            and row["spanNs"] >= cfg.min_elapsed_hours * 3_600_000_000_000):
        return ShardKeyVerdict("rekey", f"All {fan:,} observed logical queries fanned out, with starts "
                               f"in {row['occupiedHours']} distinct UTC hours spanning at least "
                               f"{cfg.min_elapsed_hours} hours.",
                               "Re-key the container to serve the recurring application lookups. "
                               "Verify the replacement key against the access patterns before migration.", evidence)
    if fan and single:
        patterns = []
        for r in rows:
            if (r.get("recordKind") == "review" and r["fanExecutions"] >= 2
                    and r["patternSpanNs"] >= MIXED_SPAN_NS):
                patterns.append(dict(query_shape=clean_query_text(r["QueryText"]),
                                     executions=r["fanExecutions"], total_ru=_cost(r),
                                     executions_per_hour=r["fanExecutions"] / observed_hours,
                                     first_start=_stamp(r["firstFan"]), last_start=_stamp(r["lastFan"])))
        if patterns:
            patterns.sort(key=lambda p: (p["total_ru"] is None, -(p["total_ru"] or 0),
                                         -p["executions"], p["query_shape"]))
            evidence["recurring_patterns"] = patterns
            p = patterns[0]
            charge = f"{p['total_ru']:,.2f} measured RU" if p["total_ru"] is not None else "total RU unknown"
            return ShardKeyVerdict("review", f"Partition-key design review: a recurring query pattern "
                                   f"fanned out {p['executions']:,} times in {observed_hours:g} hours "
                                   f"({charge}). Can the caller supply the existing partition key?",
                                   "", evidence)
    if unknown:
        return ShardKeyVerdict("incomplete", f"Query fan-out: {prefix}; {unknown:,} unclassifiable "
                               "groups prevent an all-query conclusion.", "", evidence)
    if not fan:
        return ShardKeyVerdict("scoped", f"{prefix}.", "", evidence)
    detail = f"; {'; '.join(history_issues)}" if history_issues else ""
    return ShardKeyVerdict("observation", f"{prefix}{detail}; no re-key recommendation.", "", evidence)

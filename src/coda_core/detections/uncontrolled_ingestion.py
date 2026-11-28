"""DX-010: server-side throttling during a write-heavy five-minute interval.

Write share describes the measured RU mix, not capacity utilization. Compare the 429
count with attempts of the affected operation group in the same container and interval;
never infer client identity, causation, or the application's eventual retry outcome.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import DataPlaneSource, LogAnalyticsProvider, primary_destination_filter

INTERVAL = timedelta(minutes=5)
WRITE_OPS = ("Create", "Upsert", "Replace", "Delete", "Patch", "Batch", "Execute")
OTHER_OPS = ("Read", "Head", "ReadFeed", "HeadFeed", "Query", "QueryPlan")
_GROUPS = {**{op.lower(): "writes" for op in WRITE_OPS}, **{op.lower(): op for op in OTHER_OPS}}
_UNATTRIBUTED = {"unknown", "null", "none", "unspecified", "unattributed", "undefined", "other", "writes", "reads"}
_WRITES = ", ".join(map(json.dumps, WRITE_OPS))


def _floor(stamp: datetime) -> datetime:
    """Return the beginning of the UTC five-minute bucket containing this instant."""
    stamp = stamp.astimezone(timezone.utc)
    return stamp.replace(minute=stamp.minute - stamp.minute % 5, second=0, microsecond=0)


def production_window(now: datetime | None = None, source: DataPlaneSource = DataPlaneSource.RAW) -> TimeWindow:
    """For either source, inspect the last day ending at a completed UTC boundary."""
    end = _floor(now or datetime.now(timezone.utc))
    return TimeWindow(end - timedelta(days=1), end, INTERVAL)


def _base(units: list[tuple[str, str]], source: DataPlaneSource, window: TimeWindow, resource: str) -> str:
    """Use the same exact, escaped scope and single destination for direct and cohort reads."""
    scope = " or ".join(f"(DatabaseName == {json.dumps(db, ensure_ascii=False)} "
                        f"and CollectionName == {json.dumps(c, ensure_ascii=False)})"
                        for db, c in units)
    return (
        f"{source.value} | where TimeGenerated >= datetime({window.start.isoformat()}) "
        f"and TimeGenerated < datetime({window.end.isoformat()}) "
        + primary_destination_filter(source.value, window)
        + f"| where _ResourceId =~ {json.dumps(resource)} | where {scope} "
    )


def interval_kql(units: list[tuple[str, str]], source: DataPlaneSource, window: TimeWindow, resource: str) -> str:
    """Return measured fields by named operation; never let Kusto's null-skipping sums invent zero."""
    aggregate = source is DataPlaneSource.FIVE_MINUTE
    bad_count = ("isnull(RequestCount) or not(isfinite(todouble(RequestCount))) or RequestCount <= 0 "
                 "or floor(RequestCount, 1.0) != RequestCount") if aggregate else "false"
    bad_time = "TimeGenerated != bin(TimeGenerated, 5m)" if aggregate else "false"
    bad_status = "isnull(toint(StatusCode)) or toint(StatusCode) !between (100 .. 599)"
    return (
        _base(units, source, window, resource)
        + f"| summarize attempts = {source.count}, throttled = {source.count_if('StatusCode == 429')}, "
        f"ru = sum({source.charge}), invalidCount = countif({bad_count}), "
        f"invalidCharge = countif(isnull({source.charge}) or not(isfinite({source.charge})) or {source.charge} < 0), "
        f"invalidStatus = countif({bad_status}), invalidTime = countif({bad_time}) "
        "by DatabaseName, CollectionName, bucket = bin(TimeGenerated, 5m), OperationName = tolower(OperationName)"
    )


def burst_kql(units: list[tuple[str, str]], source: DataPlaneSource, window: TimeWindow, resource: str) -> str:
    """Keep the original observed-write-bucket burst factor as separate, window-level context."""
    return (
        _base(units, source, window, resource) + f"| where OperationName in~ ({_WRITES}) "
        f"| summarize ru = sum({source.charge}) by DatabaseName, CollectionName, bin(TimeGenerated, {source.burst_interval}) "
        "| summarize peak = max(ru), avg = avg(ru) by DatabaseName, CollectionName"
    )


def user_agent_kql(units: list[tuple[str, str]], source: DataPlaneSource, window: TimeWindow, resource: str) -> str:
    """Describe the window's dominant write UserAgent without treating it as proof of Spark."""
    return (
        _base(units, source, window, resource) + f"| where OperationName in~ ({_WRITES}) "
        f"| summarize n = {source.count} by DatabaseName, CollectionName, UserAgent "
        "| sort by DatabaseName asc, CollectionName asc, n desc, UserAgent asc "
        "| serialize | extend rank = row_number(1, DatabaseName != prev(DatabaseName) or CollectionName != prev(CollectionName)) "
        "| where rank == 1 | project-away rank"
    )


@dataclass(frozen=True)
class IngestionConfig:
    """Provisional, inclusive interval policy; there is no total-attempt or age floor."""

    write_ru_pct_floor: float = 80.0
    min_throttled: int = 10
    throttle_rate_pct: float = 10.0


@dataclass(frozen=True)
class IngestionVerdict:
    """One container's strongest supported result with all observed intervals retained."""

    root_cause: str
    severity: str
    summary: str
    recommended_action: str
    methodology: dict

    @property
    def is_uncontrolled(self) -> bool:
        """Only a measured qualifying interval routes to application-side guidance."""
        return self.severity in {"medium", "high"}

    def as_dict(self) -> dict:
        """Return JSON-compatible observations without serializing internal aggregation state."""
        return asdict(self)


def _number(value, *, count=False):
    """Accept only finite nonnegative telemetry, and exact integers for represented counts."""
    if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
            or (count and int(value) != value)):
        return None
    return int(value) if count else value


def _sum(values):
    """Do not turn an unavailable contribution into a measured total."""
    values = list(values)
    return None if None in values else _number(sum(values))


def _at_least_pct(part, total, pct) -> bool:
    """Compare the represented values exactly, including counts above float precision."""
    pn, pd = part.as_integer_ratio()
    tn, td = total.as_integer_ratio()
    cn, cd = pct.as_integer_ratio()
    return 100 * pn * td * cd >= cn * tn * pd


def _interval(stamp: datetime, rows: list[dict], cfg: IngestionConfig) -> dict:
    """Retain independently measured fields; missing attribution disqualifies this interval only."""
    groups = defaultdict(list)
    by_name = defaultdict(list)
    issues = set()
    for row in rows:
        raw_name = row.get("OperationName")
        name = raw_name.strip().lower() if isinstance(raw_name, str) else ""
        if _number(row.get("invalidTime"), count=True) != 0:
            raise ValueError("Missing or misaligned source interval attribution.")
        by_name[name].append(row)
    for name, records in by_name.items():
        # A named service operation outside the write set keeps its own denominator; an
        # aggregate/unknown label is not an identified operation and cannot establish High.
        identified = name.isascii() and name.isidentifier() and name[0].isalpha() and name not in _UNATTRIBUTED
        group = _GROUPS.get(name, name) if identified else "unattributed"
        if group == "unattributed":
            issues.add("unattributed operation")
        if len(records) != 1:
            issues.add("duplicate operation aggregates")
            groups[group].append((None, None, None, None))
            continue
        row = records[0]
        attempts = (_number(row.get("attempts"), count=True)
                    if _number(row.get("invalidCount"), count=True) == 0 else None)
        if attempts == 0:
            attempts = None  # a represented operation row cannot contain no attempts
        bad_status = _number(row.get("invalidStatus"), count=True)
        known = _number(row.get("throttled"), count=True) if attempts is not None and bad_status is not None else None
        if known is not None and known > attempts:
            known = None
        throttled = known if bad_status == 0 else None
        ru = _number(row.get("ru")) if _number(row.get("invalidCharge"), count=True) == 0 else None
        if attempts is None:
            issues.add("incomplete attempt counts")
        if throttled is None:
            issues.add("incomplete 429 counts")
        if ru is None:
            issues.add("incomplete RU")
        groups[group].append((attempts, throttled, ru, known))

    counts = {}
    for group, parts in sorted(groups.items()):
        attempts, throttled, ru, known = zip(*parts)
        known = [n for n in known if n is not None]
        counts[group] = {"attempts": _sum(attempts), "server_429s": _sum(throttled), "ru": _sum(ru),
                         "observed_429s": sum(known) if known else None}
    total_ru = _sum(group["ru"] for group in counts.values())
    write_ru = None if "unattributed" in counts else counts.get("writes", {}).get("ru", 0)
    share = write_ru / total_ru * 100 if write_ru is not None and total_ru else None
    if total_ru == 0:
        issues.add("no positive measured RU for write share")
    elif total_ru is None:
        issues.add("incomplete RU")
    material = []
    for group, measured in counts.items():
        attempts, throttled = measured["attempts"], measured["server_429s"]
        if (not issues and throttled >= cfg.min_throttled
                and _at_least_pct(throttled, attempts, cfg.throttle_rate_pct)):
            material.append(group)
    dominant = share is not None and _at_least_pct(write_ru, total_ru, cfg.write_ru_pct_floor)
    severity = "none"
    if dominant and material:
        severity = "high" if any(name != "writes" for name in material) else "medium"
    return {"start_utc": stamp.isoformat(), "end_utc": (stamp + INTERVAL).isoformat(),
            "operation_groups": counts, "measured_ru": total_ru, "write_ru": write_ru, "write_ru_pct": share,
            "write_dominant": dominant if share is not None else None,
            "server_429s": _sum(group["server_429s"] for group in counts.values()),
            "material_groups": material, "severity": severity, "issues": sorted(issues)}


def _summary(interval: dict) -> str:
    """Name the witness, its exact numerators/denominators and its attribution limits."""
    groups = interval["operation_groups"]
    details = []
    for name, row in groups.items():
        n = row["server_429s"]
        if n is None:
            n = f"at least {row['observed_429s']}" if row["observed_429s"] else "unknown"
        attempts = row["attempts"] if row["attempts"] is not None else "unknown"
        details.append(f"{name}: {n} of {attempts} attempts returned HTTP 429")
    share = interval["write_ru_pct"]
    mix = (f"writes consumed {share:g}% of measured RU (provisional write-pressure proxy, not capacity utilization)"
           if share is not None else "write RU share unavailable")
    limits = f". Not graded: {', '.join(interval['issues'])}" if interval["issues"] else ""
    if not limits and interval["severity"] == "none" and interval["server_429s"]:
        limits = (". No operation group met both 429 thresholds" if interval["write_dominant"] else
                  ". The write-share proxy was not met in this interval")
    return f"{interval['start_utc']} to {interval['end_utc']}: {mix}; {'; '.join(details)}{limits}."


def classify(rows: list[dict], database: str, container: str, window: TimeWindow,
             cfg: IngestionConfig | None = None) -> IngestionVerdict:
    """Compare only contemporaneous, scoped rows; missing time buckets are never filled."""
    cfg = cfg or IngestionConfig()
    by_bucket = defaultdict(list)
    for row in rows:
        if (row.get("DatabaseName"), row.get("CollectionName")) != (database, container):
            raise ValueError("Unexpected or missing database/container attribution.")
        stamp = row.get("bucket")
        if isinstance(stamp, str):
            stamp = datetime.fromisoformat(stamp)
        if (not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp != _floor(stamp)
                or not window.start <= stamp < stamp + INTERVAL <= window.end):
            raise ValueError("Invalid or incomplete five-minute interval in scoped query result.")
        by_bucket[stamp.astimezone(timezone.utc)].append(row)
    intervals = [_interval(stamp, by_bucket[stamp], cfg) for stamp in sorted(by_bucket)]
    expected = (window.end - window.start) // INTERVAL
    incomplete = sum(bool(i["issues"]) for i in intervals)
    evidence = {"thresholds": asdict(cfg), "write_share_threshold_pct": cfg.write_ru_pct_floor,
                "group_429_threshold_pct": cfg.throttle_rate_pct, "min_group_429s": cfg.min_throttled,
                "interval": "PT5M", "expected_intervals": expected,
                "observed_intervals": len(intervals), "unobserved_intervals": expected - len(intervals),
                "incomplete_intervals": incomplete, "intervals": intervals}
    if not intervals:
        reason = "No recent data-plane traffic for this database/container."
        return IngestionVerdict("insufficient_data", "none", reason, "", {**evidence, "abstained": reason})

    def rank(interval):
        """Prefer the strongest measured episode, then observed 429s and the latest interval."""
        throttled = sum(row["observed_429s"] or 0 for row in interval["operation_groups"].values())
        return ({"high": 2, "medium": 1, "none": 0}[interval["severity"]],
                bool(throttled), bool(interval["issues"]), bool(interval["write_dominant"]),
                throttled, interval["start_utc"])

    witness = max(intervals, key=rank)
    severity = witness["severity"]
    summary = _summary(witness)
    evidence["witness_start_utc"] = witness["start_utc"]
    if incomplete:
        summary += f" {incomplete} observed interval(s) could not be graded."
    if severity != "none":
        return IngestionVerdict("uncontrolled_ingestion", severity, summary, (
            "Pace the writer: bound concurrency and honor retry-after on 429s. Consider priority or throughput "
            "buckets where supported. If you confirm this was a Spark job, consider Spark connector throughput "
            "control. Overlap does not prove which client caused throttling or that application requests failed."
        ), evidence)
    if rank(witness)[1] or (not witness["issues"] and witness["write_dominant"]):
        evidence["visible_observation"] = True
        return IngestionVerdict("observation", "none", summary, "", evidence)
    if incomplete:
        return IngestionVerdict("insufficient_data", "none", summary, "", {**evidence, "abstained": summary})
    return IngestionVerdict("not_uncontrolled", "none", summary, "", evidence)


def _supporting_context(la, resource: str, unit: tuple[str, str], window: TimeWindow,
                        source: DataPlaneSource, evidence: dict) -> None:
    """Optional window-wide measurements never erase an independently measured episode."""
    issues = []
    evidence.update(burst_interval=source.burst_interval, burst_factor=None, dominant_user_agent=None)
    if evidence["incomplete_intervals"]:
        issues.append("incomplete interval attribution; window-wide context withheld")
    else:
        for build in (burst_kql, user_agent_kql):
            try:
                rows = la.query_resource(resource, build([unit], source, window, resource), (window.start, window.end))
                if not rows:
                    continue
                row = rows[0]
                if len(rows) != 1 or (row.get("DatabaseName"), row.get("CollectionName")) != unit:
                    raise ValueError("inconsistent supporting scope")
                if build is burst_kql:
                    peak, avg = _number(row.get("peak")), _number(row.get("avg"))
                    if peak is None or avg is None or peak < avg:
                        raise ValueError("invalid burst totals")
                    evidence["burst_factor"] = peak / avg if avg else None
                else:
                    ua = row.get("UserAgent")
                    if not isinstance(ua, str) or not _number(row.get("n"), count=True):
                        raise ValueError("invalid write client measurement")
                    evidence["dominant_user_agent"] = ua or None
            except Exception as exc:  # noqa: BLE001 - optional observations are distinct from the interval evidence
                issues.append(f"{build.__name__}: {exc}")
    if issues:
        evidence["supporting_context_issues"] = issues


def detect_uncontrolled_ingestion(
    la: LogAnalyticsProvider, account_resource_id: str, database: str, container: str, window: TimeWindow,
    *, config: IngestionConfig | None = None, source: DataPlaneSource = DataPlaneSource.RAW,
    as_of: datetime | None = None,
) -> IngestionVerdict:
    """Read one selected source; report the actual completed interval coverage and any acquisition failure."""
    provenance = source.evidence(window)
    try:
        source.validate_window(window)
        start = _floor(window.start)
        if start < window.start:
            start += INTERVAL
        end = _floor(min(window.end, as_of or datetime.now(timezone.utc)))
        if start >= end:
            reason = "No completed UTC five-minute interval in the requested window."
            return IngestionVerdict("insufficient_data", "none", reason, "", {**provenance, "abstained": reason})
        effective = TimeWindow(start, end, INTERVAL)
        if (start, end) != (window.start, window.end):
            requested = provenance["observation_window"]
            provenance = {**source.evidence(effective), "requested_window": requested}
        unit = (database, container)
        rows = la.query_resource(account_resource_id, interval_kql([unit], source, effective, account_resource_id),
                                 (start, end))
        verdict = classify(rows, database, container, effective, config)
        if rows:
            _supporting_context(la, account_resource_id, unit, effective, source, verdict.methodology)
    except Exception as exc:  # noqa: BLE001 - a failed selected-source query is not a clean negative
        reason = f"Request-log query or interval attribution failed: {exc}"
        return IngestionVerdict("query_error", "none", reason, "", {**provenance, "abstained": reason})
    verdict.methodology.update(provenance)
    return verdict

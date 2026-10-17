"""DX-010: Uncontrolled ingestion / burst writes.

A write-dominant workload that is throttling is the signature of **uncontrolled ingestion** — batch /
bulk / Spark loads (or a hot write path) hammering a container faster than its throughput allows. The
fix is **application-side rate control** (bounded concurrency + retry-after, the SDK/Spark
throughput-control feature, throughput buckets, priority-based execution, queue smoothing), which is
distinct from DX-005's "provision more RU/s": you can smooth the ingestion instead of (or in addition
to) paying for the peak.

Signal & data source: **Log Analytics** ``CDBDataPlaneRequests5M`` when available, with raw
``CDBDataPlaneRequests`` compatibility. Aggregates use ``RequestCount`` and ``TotalRequestCharge``,
not row counts or unweighted means. Writes are ``Create``/``Upsert``/``Replace``/
``Delete``/``Patch``/``Execute`` (grounded against live data); everything else (``Read``/``Query``/
``QueryPlan``/``ReadFeed``/``Head``) is a read.
  * ``write_ru_pct`` = write-op RU ÷ total RU  → is the workload write-dominant?
  * ``throttle_rate`` = 429 count ÷ request count → is it throttling?
  * ``burst_factor`` = peak write RU ÷ average write RU across observed write buckets: five-minute
    buckets for aggregates, one-minute buckets for raw. The interval is explicit in evidence and
    recommendations; burstiness remains supporting evidence, not a hard gate.

Trigger: ``write_ru_pct >= 80%`` AND ``throttle_rate >= 10%``. Severity by throttle rate (>= 20% high).
The dominant write ``UserAgent`` is surfaced as context (it identifies Spark/bulk connectors when
present, but SDK strings vary so it is not a gate).

Relationship to DX-005: complementary, not exclusive. DX-005 (sustained, all-partition saturation)
says "add RU/s"; DX-010 (write-dominant throttling) says "control the ingestion rate". Both can fire on
the same container — the customer benefits from seeing the app-side lever too. Read-only / diagnose-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import DataPlaneSource, LogAnalyticsProvider

WRITE_OPS = ("Create", "Upsert", "Replace", "Delete", "Patch", "Batch", "Execute")


def production_window(
    now: datetime | None = None, source: DataPlaneSource = DataPlaneSource.RAW,
) -> TimeWindow:
    """Retain a full production day while avoiding a partial final five-minute bucket."""
    anchor = source.anchor(now or datetime.now(timezone.utc))
    return TimeWindow(anchor - timedelta(days=1), anchor, timedelta(hours=1))


def _container_base_kql(
    database: str, container: str, source: DataPlaneSource = DataPlaneSource.RAW,
    window: TimeWindow | None = None,
) -> str:
    """Shared one-container KQL predicate; runner uses these helpers for exact cache priming."""
    db = database.replace("'", "")
    coll = container.replace("'", "")
    return source.query_table(window) + f"| where DatabaseName == '{db}' and CollectionName == '{coll}' "


def _writes_literal() -> str:
    return ", ".join(f"'{w}'" for w in WRITE_OPS)


def aggregate_kql(
    database: str, container: str, source: DataPlaneSource = DataPlaneSource.RAW,
    window: TimeWindow | None = None,
) -> str:
    """KQL for DX-010's RU/request/throttle aggregate for one container."""
    return (
        _container_base_kql(database, container, source, window)
        + f"| summarize totalRu = sum({source.charge}), "
          f"writeRu = sumif({source.charge}, OperationName in ({_writes_literal()})), "
          f"reqs = {source.count}, throttles = {source.count_if('StatusCode == 429')}"
          f"{source.invalid_rows}"
    )


def burst_kql(
    database: str, container: str, source: DataPlaneSource = DataPlaneSource.RAW,
    window: TimeWindow | None = None,
) -> str:
    """KQL for write bursts at the selected source's explicitly reported resolution."""
    return (
        _container_base_kql(database, container, source, window)
        + f"| where OperationName in ({_writes_literal()}) "
          f"| summarize ru = sum({source.charge}) by bin(TimeGenerated, {source.burst_interval}) "
          "| summarize peak = max(ru), avg = avg(ru)"
    )


def user_agent_kql(
    database: str, container: str, source: DataPlaneSource = DataPlaneSource.RAW,
    window: TimeWindow | None = None,
) -> str:
    """KQL for DX-010's dominant write client lookup for one container."""
    return (
        _container_base_kql(database, container, source, window)
        + f"| where OperationName in ({_writes_literal()}) "
          f"| summarize n = {source.count} by UserAgent | top 1 by n"
    )


@dataclass(frozen=True)
class IngestionConfig:
    write_ru_pct_floor: float = 80.0   # >= this share of RU on writes = write-dominant
    throttle_rate_pct: float = 10.0    # >= this 429 rate = throttling
    severity_high_pct: float = 20.0    # >= this 429 rate = high
    min_total_requests: float = 1000.0  # below this, too little traffic to judge


@dataclass(frozen=True)
class IngestionVerdict:
    is_uncontrolled: bool
    # uncontrolled_ingestion | not_uncontrolled | insufficient_data | query_error
    root_cause: str
    write_ru_pct: float
    throttle_rate_pct: float
    burst_factor: float
    dominant_user_agent: str | None
    severity: str  # high | medium | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _abstain(root_cause: str, detail: str) -> IngestionVerdict:
    method = {"abstained": detail}
    if root_cause == "log_analytics_unavailable":
        method["la_unavailable"] = True
    return IngestionVerdict(
        is_uncontrolled=False, root_cause=root_cause, write_ru_pct=0.0, throttle_rate_pct=0.0,
        burst_factor=0.0, dominant_user_agent=None, severity="none", recommended_action="",
        methodology=method,
    )


def classify(
    write_ru: float, total_ru: float, total_requests: float, throttled_requests: float,
    burst_factor: float, dominant_user_agent: str | None,
    config: IngestionConfig | None = None,
    *,
    burst_interval: str = "1m",
) -> IngestionVerdict:
    """Map write-dominance + throttling to an uncontrolled-ingestion verdict (pure)."""
    cfg = config or IngestionConfig()
    write_ru_pct = (100.0 * write_ru / total_ru) if total_ru else 0.0
    throttle_rate = (100.0 * throttled_requests / total_requests) if total_requests else 0.0

    method = {
        "thresholds": {"write_ru_pct_floor": cfg.write_ru_pct_floor,
                       "throttle_rate_pct": cfg.throttle_rate_pct,
                       "severity_high_pct": cfg.severity_high_pct},
        "write_ru_pct": round(write_ru_pct, 1), "throttle_rate_pct": round(throttle_rate, 2),
        "burst_factor": round(burst_factor, 2), "dominant_user_agent": dominant_user_agent,
        "burst_interval": burst_interval,
    }

    if total_requests < cfg.min_total_requests:
        return _abstain("insufficient_data", f"{total_requests:.0f} requests in window")

    write_dominant = write_ru_pct >= cfg.write_ru_pct_floor
    throttling = throttle_rate >= cfg.throttle_rate_pct
    if not (write_dominant and throttling):
        return IngestionVerdict(
            is_uncontrolled=False, root_cause="not_uncontrolled", write_ru_pct=round(write_ru_pct, 1),
            throttle_rate_pct=round(throttle_rate, 2), burst_factor=round(burst_factor, 2),
            dominant_user_agent=dominant_user_agent, severity="none", recommended_action="",
            methodology=method,
        )

    severity = "high" if throttle_rate >= cfg.severity_high_pct else "medium"
    ua = f" Dominant client: `{dominant_user_agent}`." if dominant_user_agent else ""
    burst_label = "five-minute " if burst_interval == "5m" else ""
    action = (
        f"This container is write-dominant ({write_ru_pct:.0f}% of RU on writes) and throttling at "
        f"{throttle_rate:.0f}% (peak-to-average {burst_label}write burst ~{burst_factor:.1f}×), the signature of "
        f"uncontrolled ingestion.{ua} Add application-side rate control rather than only provisioning "
        f"for the peak: bound the ingestion concurrency and honor `retry-after` on 429; use the SDK's "
        f"throughput-control feature (Java local/global groups, or the Spark connector) or throughput "
        f"buckets to cap the batch path; and/or run ingestion under priority-based execution (low "
        f"priority) so it yields to the app's traffic; queue-smoothing also helps. (Raising RU/s — "
        f"DX-005 — is the complementary infrastructure lever.)"
    )
    return IngestionVerdict(
        is_uncontrolled=True, root_cause="uncontrolled_ingestion", write_ru_pct=round(write_ru_pct, 1),
        throttle_rate_pct=round(throttle_rate, 2), burst_factor=round(burst_factor, 2),
        dominant_user_agent=dominant_user_agent, severity=severity, recommended_action=action,
        methodology=method,
    )


def detect_uncontrolled_ingestion(
    la: LogAnalyticsProvider,
    account_resource_id: str,
    database: str,
    container: str,
    window: TimeWindow,
    *,
    config: IngestionConfig | None = None,
    source: DataPlaneSource = DataPlaneSource.RAW,
) -> IngestionVerdict:
    """Run DX-010 after the pipeline has established the required LA capability.

    A configured table can legitimately have no rows for this container in the 24-hour analysis
    window. That is insufficient evidence, while a query failure remains an explicit error abstention.
    """
    cfg = config or IngestionConfig()
    span = (window.start, window.end)
    try:
        source.validate_window(window)
        agg = la.query_resource(
            account_resource_id, aggregate_kql(database, container, source, window), span,
        )
        source.validate_rows(agg, counts=("reqs", "throttles"), charges=("totalRu", "writeRu"))
        burst = la.query_resource(
            account_resource_id, burst_kql(database, container, source, window), span,
        )
        ua = la.query_resource(
            account_resource_id, user_agent_kql(database, container, source, window), span,
        )
    except Exception as exc:  # noqa: BLE001 - preserve a failed detector as an explicit abstention
        verdict = _abstain("query_error", f"Log Analytics query failed: {exc}")
        verdict.methodology.update(source.evidence(window))
        return verdict

    if not agg:
        verdict = _abstain(
            "insufficient_data", "No recent data-plane traffic for this database/container."
        )
        verdict.methodology.update(source.evidence(window))
        return verdict
    row = agg[0]
    total_ru = float(row.get("totalRu") or 0.0)
    write_ru = float(row.get("writeRu") or 0.0)
    reqs = float(row.get("reqs") or 0.0)
    throttles = float(row.get("throttles") or 0.0)
    if reqs <= 0:
        verdict = _abstain(
            "insufficient_data", "No recent data-plane traffic for this database/container."
        )
        verdict.methodology.update(source.evidence(window))
        return verdict

    burst_factor = 0.0
    if burst:
        peak = float(burst[0].get("peak") or 0.0)
        avg = float(burst[0].get("avg") or 0.0)
        burst_factor = (peak / avg) if avg else 0.0

    dominant_ua = (ua[0].get("UserAgent") if ua else None) or None
    verdict = classify(
        write_ru, total_ru, reqs, throttles, burst_factor, dominant_ua, cfg,
        burst_interval=source.burst_interval,
    )
    verdict.methodology.update(source.evidence(window))
    return verdict

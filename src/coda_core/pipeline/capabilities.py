"""Capability model — what each detection needs, what's available, and *why* it can't run.

CODA degrades **honestly**: a detection that cannot run because a data source or a specific Cosmos DB
diagnostic-log table is unavailable must ABSTAIN with a clear, actionable reason — never silently
return a clean result (a tool that only emits problems can't be trusted to have looked). This module
is the single source of truth for:

  * the **capability tags** a detection can require (RBAC-class sources + per-table Log Analytics
    categories),
  * how we **resolve** which capabilities are available for a run (probing the live workspace), and
  * the human **guidance** shown when one is missing — including the legacy-mode misconfiguration.

Design decision (ADR-0026): CODA requires Cosmos DB diagnostic settings in **resource-specific** mode
(the ``CDB*`` tables). Legacy "Azure diagnostics" mode (everything in the single ``AzureDiagnostics``
table) is **detected** and the customer is **guided** to add a resource-specific setting, rather than
supported with a second query path. Gating is **per table** so a partially-configured customer (e.g.
``DataPlaneRequests`` on but ``QueryRuntimeStatistics`` off) gets "enable category X" on the exact
detections that need it — instead of a misleading "no cross-partition queries" all-clear.

Request-total consumers have an additional capability satisfied by five-minute aggregates or raw
logs. Selection prefers five-minute logs and records the source; per-request query joins still
require the raw-table capability.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from coda_core.providers.log_analytics import DataPlaneSource, LogAnalyticsQueryError

# --- Capability tags ------------------------------------------------------------------
# RBAC-class data sources (one credential role each).
CAP_METRICS = "metrics"                  # Azure Monitor metrics (Monitoring Reader)
CAP_ARM = "arm"                          # ARM control-plane read (Reader)
CAP_COST_MANAGEMENT = "cost_management"  # Cost Management / Consumption (Cost Management Reader) [FinOps]

# Physical-table capabilities remain distinct from the aggregate-compatible request capability.
CAP_LA_DATAPLANE = "la:CDBDataPlaneRequests"
CAP_LA_QUERYSTATS = "la:CDBQueryRuntimeStatistics"
# Aggregate-only detectors can use either source; raw remains mandatory for activity-ID joins.
CAP_LA_REQUEST_AGGREGATES = "la:request_aggregates"


@dataclass(frozen=True)
class Capability:
    """One capability CODA can require, plus the guidance shown when it is missing."""

    key: str
    label: str                    # human name for reports
    enable_hint: str              # actionable guidance when missing
    la_table: str | None = None   # resource-specific table, if this is a Log Analytics capability
    category: str | None = None   # Cosmos DB diagnostic-setting category that populates ``la_table``

    @property
    def is_log_analytics(self) -> bool:
        return self.la_table is not None


CAPABILITIES: dict[str, Capability] = {
    CAP_METRICS: Capability(
        CAP_METRICS, "Azure Monitor metrics",
        "Grant 'Monitoring Reader' on the Cosmos DB account.",
    ),
    CAP_ARM: Capability(
        CAP_ARM, "ARM control-plane read",
        "Grant 'Reader' on the Cosmos DB account.",
    ),
    CAP_COST_MANAGEMENT: Capability(
        CAP_COST_MANAGEMENT, "Cost Management",
        "Grant 'Cost Management Reader' on the subscription.",
    ),
    CAP_LA_DATAPLANE: Capability(
        CAP_LA_DATAPLANE, "Data-plane request logs",
        "Enable the 'DataPlaneRequests' category in **resource-specific** mode on the account's "
        "diagnostic settings (populates CDBDataPlaneRequests).",
        la_table="CDBDataPlaneRequests", category="DataPlaneRequests",
    ),
    CAP_LA_QUERYSTATS: Capability(
        CAP_LA_QUERYSTATS, "Query runtime statistics logs",
        "Enable the 'QueryRuntimeStatistics' category in **resource-specific** mode on the account's "
        "diagnostic settings (populates CDBQueryRuntimeStatistics).",
        la_table="CDBQueryRuntimeStatistics", category="QueryRuntimeStatistics",
    ),
    CAP_LA_REQUEST_AGGREGATES: Capability(
        CAP_LA_REQUEST_AGGREGATES, "Request-log aggregates",
        "Enable 'DataPlaneRequests5M' in **resource-specific** mode "
        "(CDBDataPlaneRequests5M). Existing raw DataPlaneRequests logs are also supported.",
        la_table="CDBDataPlaneRequests5M", category="DataPlaneRequests5M",
    ),
}

# All per-table Log Analytics capabilities (the set we probe to diagnose diagnostic-settings mode).
LA_CAPABILITIES: frozenset[str] = frozenset(
    k for k, c in CAPABILITIES.items() if c.is_log_analytics
)

# --- Log Analytics diagnostic-settings mode diagnosis ---------------------------------
LA_OK = "ok"                  # every required resource-specific table is present
LA_NO_PROVIDER = "no_provider"  # no Log Analytics provider supplied to the run at all
LA_NOT_ENABLED = "not_enabled"  # no CDB* rows and no Cosmos rows in AzureDiagnostics → settings off
LA_LEGACY_MODE = "legacy_mode"  # no CDB* rows but Cosmos rows exist in AzureDiagnostics → wrong mode
LA_PARTIAL = "partial"          # some required CDB* tables present, at least one missing (category off)
LA_PROBE_ERROR = "probe_error"  # table availability could not be established because a read failed


@dataclass(frozen=True)
class LogTableObservation:
    """One actual table probe; callers must not equate missing rows with missing configuration."""

    table: str
    state: str
    row_count: int = 0
    last_seen: datetime | None = None
    error: str | None = None
    error_type: str | None = None
    http_status: int | None = None
    service_code: str | None = None


def log_source_tables(capability: str) -> tuple[str, ...]:
    """Return accepted physical tables in preference order, shared by diagnosis and readiness."""
    if capability == CAP_LA_REQUEST_AGGREGATES:
        return (DataPlaneSource.FIVE_MINUTE.value, DataPlaneSource.RAW.value)
    descriptor = CAPABILITIES[capability]
    if descriptor.la_table is None:
        raise ValueError(f"Not a Log Analytics capability: {capability}")
    return (descriptor.la_table,)


def la_mode_guidance(mode: str, missing_tables: frozenset[str]) -> str:
    """One actionable sentence explaining an LA shortfall, tailored to the misconfiguration."""
    cats = ", ".join(sorted(
        c.category for c in CAPABILITIES.values()
        if c.la_table in missing_tables and c.category
    )) or "the required"
    if mode == LA_NO_PROVIDER or mode == LA_NOT_ENABLED:
        return ("CODA has no accessible records for the required resource logs. Verify a diagnostic "
                f"setting in **resource-specific** mode with the {cats} category(ies) and a Log "
                "Analytics destination. If already configured, check activity, ingestion and access.")
    if mode == LA_LEGACY_MODE:
        return ("Only legacy **AzureDiagnostics** records were found; these checks need "
                "**resource-specific** tables. Verify resource-specific collection with the "
                f"{cats} category(ies), including activity and ingestion if already configured.")
    if mode == LA_PARTIAL:
        return (f"No accessible records were found for the {cats} category(ies). Verify "
                "**resource-specific** diagnostic settings, activity, ingestion and access.")
    return ""


@dataclass(frozen=True)
class CapabilitySet:
    """The capabilities available for one run, plus the LA diagnostic-settings diagnosis."""

    available: frozenset[str]
    la_mode: str = LA_OK                          # LA_* constant
    missing_tables: frozenset[str] = frozenset()  # required LA tables that are absent/empty
    probe_errors: tuple[tuple[str, str], ...] = ()  # capability key + bounded provider error
    dataplane_source: DataPlaneSource | None = None
    table_observations: tuple[LogTableObservation, ...] = ()

    def has(self, capability: str) -> bool:
        return capability in self.available

    def missing(self, requires: frozenset[str]) -> frozenset[str]:
        """Which of a detection's required capabilities are unavailable this run."""
        return frozenset(requires) - self.available

    def probe_error_for(self, capabilities: frozenset[str]) -> str | None:
        """Return the first capability-probe error affecting ``capabilities``, if any."""
        errors = self.probe_errors_for(capabilities)
        return errors[0][1] if errors else None

    def probe_errors_for(self, capabilities: frozenset[str]) -> tuple[tuple[str, str], ...]:
        """Return every capability-probe error affecting ``capabilities``."""
        affected = set(capabilities)
        return tuple((cap, error) for cap, error in self.probe_errors if cap in affected)

    def guidance_for(self, missing_caps: frozenset[str]) -> str:
        """Actionable guidance for a set of missing capabilities (LA-aware, else per-cap hints)."""
        la_missing = frozenset(
            CAPABILITIES[c].la_table for c in missing_caps
            if c in CAPABILITIES and CAPABILITIES[c].is_log_analytics
        )
        if la_missing:
            guidance = la_mode_guidance(self.la_mode, la_missing)
            if guidance:
                return guidance
            # A simultaneous probe error prevents a global LA-mode diagnosis, but a typed semantic
            # failure still proves each listed table absent. Keep that category-specific guidance.
            return " ".join(
                CAPABILITIES[c].enable_hint
                for c in sorted(missing_caps)
                if c in CAPABILITIES and CAPABILITIES[c].is_log_analytics
            )
        hints = [CAPABILITIES[c].enable_hint for c in sorted(missing_caps) if c in CAPABILITIES]
        return " ".join(hints)


def probe_log_table(
    probe: Callable[[str], list[dict]], table: str, *, include_latest: bool = False,
) -> LogTableObservation:
    """Observe table access without inventing configuration facts or swallowing read failures.

    Ordinary diagnosis retains its existing count-only query. Readiness also requests the latest
    record timestamp; neither result proves continuous collection or detector-level sample sufficiency.
    """
    try:
        suffix = ", last_seen = max(TimeGenerated)" if include_latest else ""
        rows = probe(f"{table} | summarize n = count(){suffix}")
        if not rows:
            return LogTableObservation(table, "empty")
        count = rows[0].get("n")
        if (
            isinstance(count, bool) or not isinstance(count, (int, float))
            or not math.isfinite(count) or count < 0 or int(count) != count
        ):
            raise ValueError("Log table probe returned an invalid row count.")
        latest = rows[0].get("last_seen") if include_latest else None
        if include_latest and count == 0 and latest is not None:
            raise ValueError("An empty log table probe returned a last-record timestamp.")
        if include_latest and count > 0 and (
            not isinstance(latest, datetime) or latest.tzinfo is None
        ):
            raise ValueError("Log table probe returned an invalid last-record timestamp.")
        return LogTableObservation(
            table, "present" if count else "empty", int(count),
            latest.astimezone(timezone.utc) if latest is not None else None,
        )
    except LogAnalyticsQueryError as exc:
        if exc.is_missing_table:
            return LogTableObservation(table, "missing")
        return LogTableObservation(
            table, "error", error=f"{type(exc).__name__}: {exc}"[:500],
            error_type=type(exc).__name__, service_code=exc.code,
        )
    except Exception as exc:  # noqa: BLE001 - transport/auth/provider failures remain explicit errors
        return LogTableObservation(
            table, "error", error=f"{type(exc).__name__}: {exc}"[:500],
            error_type=type(exc).__name__, http_status=getattr(exc, "status_code", None),
            service_code=getattr(getattr(exc, "error", None), "code", None),
        )


def _table_probe(
    probe: Callable[[str], list[dict]], table: str,
) -> tuple[bool, str | None]:
    """Preserve the existing capability-probe contract over shared observation handling."""
    result = probe_log_table(probe, table)
    return result.row_count > 0, result.error


def resolve_capabilities(
    *,
    la,  # LogAnalyticsProvider | None
    account_resource_id: str,
    span: tuple[datetime, datetime],
    required_la_caps: frozenset[str] = LA_CAPABILITIES,
    metrics_available: bool = True,
    arm_available: bool = True,
    cost_available: bool = False,
    include_latest: bool = False,
) -> CapabilitySet:
    """Resolve the available capabilities for one account, probing the live workspace once per table.

    Metrics/ARM/Cost are RBAC-class and supplied by the caller (the providers exist iff the role does).
    Log Analytics is probed at **table** granularity so gating and guidance are category-precise; the
    diagnostic-settings *mode* (ok / partial / legacy / not-enabled) is derived from which tables and
    whether legacy ``AzureDiagnostics`` carries Cosmos rows.
    """
    available: set[str] = set()
    if metrics_available:
        available.add(CAP_METRICS)
    if arm_available:
        available.add(CAP_ARM)
    if cost_available:
        available.add(CAP_COST_MANAGEMENT)

    required_la_caps = frozenset(required_la_caps)
    if la is None:
        missing = frozenset(CAPABILITIES[c].la_table for c in required_la_caps)
        return CapabilitySet(frozenset(available), LA_NO_PROVIDER, missing)

    def probe(kql: str) -> list[dict]:
        return la.query_resource(account_resource_id, kql, span)

    table_results: dict[str, LogTableObservation] = {}

    def table_probe(table: str) -> tuple[bool, str | None]:
        """Probe a physical table once even when it satisfies multiple capabilities."""
        if table not in table_results:
            table_results[table] = probe_log_table(probe, table, include_latest=include_latest)
        result = table_results[table]
        return result.row_count > 0, result.error

    present: dict[str, bool] = {}
    probe_errors: dict[str, str] = {}
    dataplane_source = None
    for cap in sorted(required_la_caps):
        for table in log_source_tables(cap):
            has_rows, error = table_probe(table)
            if has_rows or error is not None:
                break
        if cap == CAP_LA_REQUEST_AGGREGATES and has_rows:
            dataplane_source = DataPlaneSource(table)
        if has_rows:
            present[cap] = True
            available.add(cap)
        else:
            present[cap] = False
            if error:
                probe_errors[cap] = error

    if probe_errors:
        mode = LA_PROBE_ERROR
    elif all(present.values()):
        mode = LA_OK
    elif all(not v for v in present.values()):
        # Nothing resource-specific at all → distinguish "wrong mode" from "not enabled".
        legacy_rows, legacy_error = table_probe("AzureDiagnostics")
        if legacy_error:
            mode = LA_PROBE_ERROR
            for cap in required_la_caps:
                probe_errors[cap] = f"AzureDiagnostics probe failed: {legacy_error}"[:500]
        else:
            mode = LA_LEGACY_MODE if legacy_rows else LA_NOT_ENABLED
    else:
        mode = LA_PARTIAL
    missing_tables = frozenset(
        CAPABILITIES[c].la_table
        for c in required_la_caps
        if not present[c] and c not in probe_errors
    )
    return CapabilitySet(
        frozenset(available), mode, missing_tables, tuple(sorted(probe_errors.items())),
        dataplane_source,
        tuple(table_results.values()),
    )


__all__ = [
    "CAP_METRICS", "CAP_ARM", "CAP_COST_MANAGEMENT", "CAP_LA_DATAPLANE", "CAP_LA_QUERYSTATS",
    "CAP_LA_REQUEST_AGGREGATES",
    "LogTableObservation", "probe_log_table", "log_source_tables",
    "Capability", "CAPABILITIES", "LA_CAPABILITIES",
    "LA_OK", "LA_NO_PROVIDER", "LA_NOT_ENABLED", "LA_LEGACY_MODE", "LA_PARTIAL", "LA_PROBE_ERROR",
    "CapabilitySet", "resolve_capabilities", "la_mode_guidance",
]

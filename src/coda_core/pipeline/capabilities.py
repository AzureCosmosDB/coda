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
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from coda_core.providers.log_analytics import LogAnalyticsQueryError

# --- Capability tags ------------------------------------------------------------------
# RBAC-class data sources (one credential role each).
CAP_METRICS = "metrics"                  # Azure Monitor metrics (Monitoring Reader)
CAP_ARM = "arm"                          # ARM control-plane read (Reader)
CAP_COST_MANAGEMENT = "cost_management"  # Cost Management / Consumption (Cost Management Reader) [FinOps]

# Per-table Log Analytics capabilities. The tag *is* the data dependency at table granularity, so a
# detection requires exactly the resource-specific table(s) it queries.
CAP_LA_DATAPLANE = "la:CDBDataPlaneRequests"
CAP_LA_QUERYSTATS = "la:CDBQueryRuntimeStatistics"


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


def la_mode_guidance(mode: str, missing_tables: frozenset[str]) -> str:
    """One actionable sentence explaining an LA shortfall, tailored to the misconfiguration."""
    cats = ", ".join(sorted(
        c.category for c in CAPABILITIES.values()
        if c.la_table in missing_tables and c.category
    )) or "the required"
    if mode == LA_NO_PROVIDER or mode == LA_NOT_ENABLED:
        return ("Cosmos DB diagnostic settings are not exporting resource logs. Add a diagnostic "
                f"setting in **resource-specific** mode with the {cats} category(ies) to a Log "
                "Analytics workspace.")
    if mode == LA_LEGACY_MODE:
        return ("Diagnostic logs are going to the legacy **AzureDiagnostics** table; CODA needs "
                "**resource-specific** tables. Add a second diagnostic setting in resource-specific "
                f"mode with the {cats} category(ies) (a resource can have multiple settings).")
    if mode == LA_PARTIAL:
        return (f"Enable the {cats} category(ies) in **resource-specific** mode on the account's "
                "diagnostic settings — they are currently off, so these detections cannot run.")
    return ""


@dataclass(frozen=True)
class CapabilitySet:
    """The capabilities available for one run, plus the LA diagnostic-settings diagnosis."""

    available: frozenset[str]
    la_mode: str = LA_OK                          # LA_* constant
    missing_tables: frozenset[str] = frozenset()  # required LA tables that are absent/empty
    probe_errors: tuple[tuple[str, str], ...] = ()  # capability key + bounded provider error

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


def _table_probe(
    probe: Callable[[str], list[dict]], table: str
) -> tuple[bool, str | None]:
    """Return row presence plus any real read failure for one table.

    Log Analytics reports an unconfigured table as a semantic "could not be resolved" error; that is
    genuine capability absence. Other exceptions are provider/read failures and must not be presented
    as diagnostic-settings configuration advice.
    """
    try:
        rows = probe(f"{table} | summarize n = count()")
    except LogAnalyticsQueryError as exc:
        if exc.is_missing_table:
            return False, None
        return False, f"{type(exc).__name__}: {exc}"[:500]
    except Exception as exc:  # noqa: BLE001 - transport/auth/provider failures remain explicit errors
        detail = str(exc)
        return False, f"{type(exc).__name__}: {detail}"[:500]
    return bool(rows) and (rows[0].get("n") or 0) > 0, None


def resolve_capabilities(
    *,
    la,  # LogAnalyticsProvider | None
    account_resource_id: str,
    span: tuple[datetime, datetime],
    required_la_caps: frozenset[str] = LA_CAPABILITIES,
    metrics_available: bool = True,
    arm_available: bool = True,
    cost_available: bool = False,
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

    present: dict[str, bool] = {}
    probe_errors: dict[str, str] = {}
    for cap in sorted(required_la_caps):
        table = CAPABILITIES[cap].la_table
        has_rows, error = _table_probe(probe, table)
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
        legacy_rows, legacy_error = _table_probe(probe, "AzureDiagnostics")
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
        frozenset(available), mode, missing_tables, tuple(sorted(probe_errors.items()))
    )


__all__ = [
    "CAP_METRICS", "CAP_ARM", "CAP_COST_MANAGEMENT", "CAP_LA_DATAPLANE", "CAP_LA_QUERYSTATS",
    "Capability", "CAPABILITIES", "LA_CAPABILITIES",
    "LA_OK", "LA_NO_PROVIDER", "LA_NOT_ENABLED", "LA_LEGACY_MODE", "LA_PARTIAL", "LA_PROBE_ERROR",
    "CapabilitySet", "resolve_capabilities", "la_mode_guidance",
]

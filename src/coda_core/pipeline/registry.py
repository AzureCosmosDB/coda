"""Detection registry: applicability + verdict→Finding adapters.

Each detection is wrapped in a small adapter that (a) declares which units it *applies* to and
(b) runs the detection and translates its bespoke verdict into the uniform :class:`Finding`.

Dependency direction is deliberate: the **pipeline depends on the detections**, never the reverse.
Detections stay pure (no knowledge of Finding/report); the translation lives here. Adding a new
detection to the end-to-end flow is one entry in :data:`REGISTRY`.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from coda_core.detections import autoscale_signal as asig
from coda_core.detections import consistency as cons
from coda_core.detections import cross_partition_query as cpq
from coda_core.detections import error_analysis as ea
from coda_core.detections import hot_partition as hp
from coda_core.detections import idle_container as idle
from coda_core.detections import indexing_cost as ic
from coda_core.detections import mode_switch as ms
from coda_core.detections import multi_region_write as mrw
from coda_core.detections import over_provisioning as op
from coda_core.detections import partition_merge as pm
from coda_core.detections import per_region_autoscale as prpa
from coda_core.detections import pitr_backup as pitr
from coda_core.detections.pitr_savings import select_complete_storage_snapshot
from coda_core.detections import reserved_capacity as rc
from coda_core.detections import serverless_candidate as svc
from coda_core.detections import serverless_throttling as svt
from coda_core.detections import shard_key_misalignment as skm
from coda_core.detections import shared_throughput as sht
from coda_core.detections import storage_growth as sg
from coda_core.detections import storage_skew as ss
from coda_core.detections import throttling_root_cause as trc
from coda_core.detections import uncontrolled_ingestion as ui
from coda_core.detections import under_provisioning as up
from coda_core.framework.cost_rate import (
    APPROVED_EFFECTIVE_RATE_SCOPES,
    RATE_SOURCE_CUSTOMER_AMORTIZED_BILL,
    monthly_savings,
)
from coda_core.pipeline.capabilities import (
    CAP_LA_DATAPLANE,
    CAP_LA_QUERYSTATS,
    CAP_LA_REQUEST_AGGREGATES,
    CAPABILITIES,
    CapabilitySet,
)
from coda_core.pipeline.context import (
    AccountDetectionContext,
    DatabaseDetectionContext,
    DetectionContext,
    InventoryDetectionContext,
    ServerlessDetectionContext,
)
from coda_core.pipeline.finding import (
    STATUS_ABSTAINED,
    STATUS_FINDING,
    STATUS_NOT_DETECTED,
    THRESHOLD_PROPOSAL,
    THRESHOLD_VALIDATED,
    Finding,
    UnitRef,
)
from coda_core.providers.arm import ThroughputOffer
from coda_core.providers.base import TimeWindow
from coda_core.providers.retail_prices import (
    PITR_STORAGE_METER_NAME,
    PITR_UNIT,
    RETAIL_PRICES_BASE_URL,
)


# Detectors whose severity CUTOFFS are grounded against internal fleet telemetry
# (docs/evidence/threshold-grounding.md) or are deterministic config facts (no statistical cutoff).
# Every other detection is THRESHOLD_PROPOSAL until its cutoffs are fleet-grounded — this is the single
# source of truth, applied as a policy pass in the runner so the customer report never overclaims.
THRESHOLD_VALIDATED_DETECTIONS = frozenset({
    "DX-001",  # over-provisioning: 1%/5% materiality + 30% peak (fleet-utilization-distribution.md)
    "DX-002",  # structural fan-out (avg fan-out ≥1.5, ≥10% share), severity by partitions × rate (ADR-0068)
    "DX-003",  # shared-pool monopolization 60% (55% of shared DBs) + throttle (grounded)
    "DX-004",  # idle ≈ 0 requests (definitional)
    "DX-005",  # throttle 5%/20% ≈ p25/p50 of fleet throttle dist; 90% saturation = 99.8% fleet
    "DX-006",  # shares DX-005's fleet-validated 90% saturation cutoff
    "DX-007",  # structural shard-key misalignment: ≥60% fan-out share, reuses DX-002 severity (ADR-0068)
    "DX-008",  # multi-region-writes config fact (deterministic)
    "DX-009",  # partition-merge: multi-partition + low RU (86% of multi-partition are ≤6000 RU)
    "DX-010",  # uncontrolled ingestion: write-RU ≥80% (20.2% of fleet; per-op RU telemetry) + throttle ≥10%/20%
    "DX-011",  # autoscale max over-provisioned: peak <30% of max (74% of autoscale fleet; autoscale RU telemetry)
    "DX-012",  # manual→autoscale: bursty peak/avg ≥5 (8.4% of manual fleet)
    "DX-013",  # autoscale→manual: steady avg ≥66% & ratio ≤1.3 (3.3% of autoscale fleet)
    "DX-014",  # serverless sporadic <10% avg/peak (70% of fleet) + verified 5,000 RU/s ceiling
    "DX-015",  # storage skew: 0.7 balance (13.2% of multi-partition) + 40/25 GiB of verified 50 GiB
    "DX-016",  # consistency-level config fact (deterministic)
    "DX-017",  # storage growth: <30d/<90d-to-50GiB horizons (13.3%/43% of growing material partitions)
    "DX-018",  # serverless throttle 5%/20% (fleet throttle distribution)
    "DX-019",  # paid continuous tier + non-production config facts (deterministic)
    "DX-022",  # multi-region + provisioned + PRPA-disabled config facts (deterministic)
    "DX-024",  # index/data >0.3 Low (27.5% of fleet), >1.0 Medium (3.3%) (dx024-indexing-ratio.md)
})

# Conditional investigation only: account status counts do not establish a request sequence.
DX020_AGENT_KIT_RULES = {
    404: "sdk-conditional-create-etag",
    409: "sdk-conditional-create-etag",
    412: "sdk-etag-concurrency",
}


def dx020_agent_kit_rule(status: str, dominant_code: int | None) -> str | None:
    """Select verified guidance only for findings dominated by an explicitly mapped status."""
    if status != STATUS_FINDING or dominant_code is None:
        return None
    return DX020_AGENT_KIT_RULES.get(dominant_code)


# Finding-only remediation routing for DX-021's detector-authored dominant category.
DX021_AGENT_KIT_RULES = {
    "write": "sdk-ingestion-rate-control",
    "read": "partition-avoid-hotspots",
    "query": "query-avoid-cross-partition",
    "execute": "monitoring-ru-consumption",
    "other": "monitoring-throttling",
}


def dx021_agent_kit_rule(status: str, dominant_category: str | None) -> str | None:
    """Map a DX-021 finding to remediation; clean and abstained results never emit a rule."""
    if status != STATUS_FINDING:
        return None
    return DX021_AGENT_KIT_RULES.get(dominant_category or "other", DX021_AGENT_KIT_RULES["other"])


def threshold_status_for(detection_id: str) -> str:
    """Fleet-grounded/config-deterministic → validated; otherwise proposal (honest by default)."""
    return THRESHOLD_VALIDATED if detection_id in THRESHOLD_VALIDATED_DETECTIONS else THRESHOLD_PROPOSAL


@dataclass(frozen=True)
class DetectionAdapter:
    detection_id: str
    title: str
    applies: Callable[[ThroughputOffer], bool]
    run: Callable[[DetectionContext], Finding]
    requires: frozenset[str] = frozenset()


@dataclass(frozen=True)
class AccountDetectionAdapter:
    """An account-scoped detection (config/state); runs once per account, not per container."""

    detection_id: str
    title: str
    run: Callable[[AccountDetectionContext], Finding]
    requires: frozenset[str] = frozenset()
    optional_requires: frozenset[str] = frozenset()


@dataclass(frozen=True)
class DatabaseDetectionAdapter:
    """A database-scoped detection (shared-throughput databases); runs once per shared database."""

    detection_id: str
    title: str
    run: Callable[[DatabaseDetectionContext], Finding]
    requires: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ServerlessDetectionAdapter:
    """A serverless-container detection (DX-018); runs per container in a serverless account."""

    detection_id: str
    title: str
    run: Callable[[ServerlessDetectionContext], Finding]
    requires: frozenset[str] = frozenset()


@dataclass(frozen=True)
class InventoryDetectionAdapter:
    """An all-container detection (DX-024); runs per ARM-enumerated container, any throughput model."""

    detection_id: str
    title: str
    run: Callable[[InventoryDetectionContext], Finding]
    requires: frozenset[str] = frozenset()


def _account_unit(ctx: AccountDetectionContext) -> UnitRef:
    return UnitRef(account=ctx.account, database="", container=None, level="account",
                   resource_id=ctx.account_resource_id)


def _database_unit(ctx: DatabaseDetectionContext) -> UnitRef:
    return UnitRef(account=ctx.account, database=ctx.database, container=None, level="database",
                   resource_id=f"{ctx.account_resource_id}/sqlDatabases/{ctx.database}")


def _serverless_unit(ctx: ServerlessDetectionContext) -> UnitRef:
    return UnitRef(
        account=ctx.account, database=ctx.database, container=ctx.container, level="container",
        resource_id=(f"{ctx.account_resource_id}/sqlDatabases/{ctx.database}"
                     f"/containers/{ctx.container}"),
    )


def _inventory_unit(ctx: InventoryDetectionContext) -> UnitRef:
    c = ctx.container
    return UnitRef(
        account=ctx.account, database=c.database, container=c.container, level="container",
        resource_id=f"{ctx.account_resource_id}/sqlDatabases/{c.database}/containers/{c.container}",
    )


def _unit(ctx: DetectionContext) -> UnitRef:
    o = ctx.offer
    rid = f"{ctx.account_resource_id}/sqlDatabases/{o.database}"
    if o.container:
        rid += f"/containers/{o.container}"
    return UnitRef(account=ctx.account, database=o.database, container=o.container, level=o.level,
                   resource_id=rid)


def _is_positive_finite(value: object) -> bool:
    """Return whether ``value`` is a real, finite quantity greater than zero."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def _savings_fields(
    ctx: DetectionContext | AccountDetectionContext,
    recoverable_ru: float | None,
) -> dict:
    """Translate removable capacity into bill-derived dollar fields, or empty when not defensible.

    Returns kwargs for :class:`Finding` (``estimated_monthly_savings``/``savings_currency``) plus an
    ``evidence`` fragment recording the effective rate, so every dollar figure is auditable back to
    the customer's amortized bill, including its approved account or subscription-fallback scope.
    Empty dict when Cost Management is unavailable, provenance is incomplete, or the finding has no
    positive finite capacity — the finding then stays capacity-only (never a fabricated dollar).
    """
    rate = ctx.effective_rate
    if (
        rate is None
        or not _is_positive_finite(recoverable_ru)
        or not _is_positive_finite(rate.usd_per_ru_month)
        or not isinstance(rate.currency, str)
        or not rate.currency.strip()
        or not isinstance(rate.basis, dict)
        or rate.rate_scope not in APPROVED_EFFECTIVE_RATE_SCOPES
        or rate.basis.get("rate_source") != RATE_SOURCE_CUSTOMER_AMORTIZED_BILL
        or rate.basis.get("rate_scope") != rate.rate_scope
    ):
        return {}
    amount = monthly_savings(recoverable_ru, rate)
    rounded_amount = round(amount, 2) if amount is not None else None
    if not _is_positive_finite(rounded_amount):
        return {}
    return {
        "estimated_monthly_savings": rounded_amount,
        "savings_currency": rate.currency,
        "savings_basis": "customer_amortized_bill",
        "evidence": {
            "estimated_monthly_savings": rounded_amount,
            "savings_currency": rate.currency,
            "effective_rate_usd_per_ru_month": rate.usd_per_ru_month,
            "rate_basis": rate.basis,
        },
    }


def _savings_summary(amount: float | None, currency: str | None) -> str:
    """A human '(~$X/month at your effective rate)' clause, or '' when no dollar figure.

    Kept for callers/surfaces that render a finding's summary in isolation (without the report's
    structured meta line). The markdown report shows the dollar figure in its own meta line, so it
    does not append this — avoiding a double-print.
    """
    if amount is None:
        return ""
    return f" (~{amount:,.2f} {currency}/month at your effective rate)"


def _is_container(offer: ThroughputOffer) -> bool:
    return offer.level == "container"


def _is_metrics_scoped(offer: ThroughputOffer) -> bool:
    """A metrics-based offer: a dedicated container OR a shared-throughput database offer.

    The shared-DB variants (idle/over/under-provisioning, hot partition) reuse the container
    detectors at database scope — the offer's metrics are read with a ``DatabaseName``-only filter
    (the shared offer reports ``NormalizedRUConsumption`` under the database with an empty
    ``CollectionName``)."""
    return offer.level in ("container", "database")


# --- Graceful degradation: one detection's failure must never abort the whole run ------

def _error_finding(detection_id: str, title: str, unit: UnitRef, exc: Exception) -> Finding:
    """An unexpected detection error degrades to an ABSTAINED finding (not a crashed run).

    The error is captured in evidence for diagnosis; it is *not* flagged ``la_unavailable`` (so it
    doesn't wrongly trip the report's "enable Log Analytics" guardrail).
    """
    return Finding(
        detection_id=detection_id, title=title, unit=unit, status=STATUS_ABSTAINED, severity="none",
        summary=f"Insufficient data: detection error ({type(exc).__name__})",
        recommended_action="", agent_kit_rule=None, threshold_status=THRESHOLD_VALIDATED,
        evidence={"abstained": "detection_error", "error": str(exc)[:500]},
    )


def gated_finding(
    detection_id: str, title: str, unit: UnitRef, missing: frozenset[str], caps: CapabilitySet,
) -> Finding:
    """A detection skipped because a required capability is unavailable → ABSTAINED, with a clear,
    actionable reason (which capability/diagnostic-category to enable). LA shortfalls also set
    ``la_unavailable`` so the report's consolidated diagnostic-settings callout picks them up.
    """
    probe_errors = caps.probe_errors_for(missing)
    errored = frozenset(cap for cap, _ in probe_errors)
    unavailable = missing - errored
    guidance = caps.guidance_for(unavailable)
    reasons = []
    if probe_errors:
        errors = "; ".join(
            f"{CAPABILITIES[cap].label if cap in CAPABILITIES else cap}: {error}"
            for cap, error in probe_errors
        )
        reasons.append(f"Log Analytics probe failed for {errors}")
    if guidance:
        reasons.append(guidance)
    if not reasons:
        labels = ", ".join(
            CAPABILITIES[cap].label if cap in CAPABILITIES else cap for cap in sorted(missing)
        )
        reasons.append(f"Required capability unavailable: {labels}")
    la_missing = any(c.startswith("la:") for c in unavailable)
    evidence = {
        "abstained": "capability_probe_error" if probe_errors else "capability_unavailable",
    }
    if unavailable:
        evidence["capability_unavailable"] = sorted(unavailable)
    if guidance:
        evidence["guidance"] = guidance
    if probe_errors:
        evidence["probe_errors"] = dict(probe_errors)
        evidence["error"] = "; ".join(error for _, error in probe_errors)
    if la_missing:
        evidence["la_unavailable"] = True
        evidence["la_mode"] = caps.la_mode
    return Finding(
        detection_id=detection_id, title=title, unit=unit, status=STATUS_ABSTAINED, severity="none",
        summary=f"Insufficient data: {' '.join(reasons)}", recommended_action="", agent_kit_rule=None,
        threshold_status=THRESHOLD_VALIDATED, evidence=evidence,
    )


def run_account(
    adapter: AccountDetectionAdapter, ctx: AccountDetectionContext, caps: CapabilitySet | None = None,
) -> Finding:
    if caps is not None and (missing := caps.missing(adapter.requires)):
        return gated_finding(adapter.detection_id, adapter.title, _account_unit(ctx), missing, caps)
    try:
        return adapter.run(ctx)
    except Exception as exc:  # noqa: BLE001 - degrade gracefully; never abort the run
        return _error_finding(adapter.detection_id, adapter.title, _account_unit(ctx), exc)


def run_database(
    adapter: DatabaseDetectionAdapter, ctx: DatabaseDetectionContext, caps: CapabilitySet | None = None,
) -> Finding:
    if caps is not None and (missing := caps.missing(adapter.requires)):
        return gated_finding(adapter.detection_id, adapter.title, _database_unit(ctx), missing, caps)
    try:
        return adapter.run(ctx)
    except Exception as exc:  # noqa: BLE001
        return _error_finding(adapter.detection_id, adapter.title, _database_unit(ctx), exc)


def run_container(
    adapter: DetectionAdapter, ctx: DetectionContext, caps: CapabilitySet | None = None,
) -> Finding:
    if caps is not None and (missing := caps.missing(adapter.requires)):
        return gated_finding(adapter.detection_id, adapter.title, _unit(ctx), missing, caps)
    try:
        return adapter.run(ctx)
    except Exception as exc:  # noqa: BLE001
        return _error_finding(adapter.detection_id, adapter.title, _unit(ctx), exc)


def run_serverless(
    adapter: ServerlessDetectionAdapter, ctx: ServerlessDetectionContext,
    caps: CapabilitySet | None = None,
) -> Finding:
    if caps is not None and (missing := caps.missing(adapter.requires)):
        return gated_finding(adapter.detection_id, adapter.title, _serverless_unit(ctx), missing, caps)
    try:
        return adapter.run(ctx)
    except Exception as exc:  # noqa: BLE001
        return _error_finding(adapter.detection_id, adapter.title, _serverless_unit(ctx), exc)


def run_inventory(
    adapter: InventoryDetectionAdapter, ctx: InventoryDetectionContext,
    caps: CapabilitySet | None = None,
) -> Finding:
    if caps is not None and (missing := caps.missing(adapter.requires)):
        return gated_finding(adapter.detection_id, adapter.title, _inventory_unit(ctx), missing, caps)
    try:
        return adapter.run(ctx)
    except Exception as exc:  # noqa: BLE001
        return _error_finding(adapter.detection_id, adapter.title, _inventory_unit(ctx), exc)


# --- DX-002: cross-partition query fan-out (Log Analytics; container + serverless) ----

def _dx002_finding(
    la, account_resource_id: str, database: str, container: str, window, unit: UnitRef,
) -> Finding:
    """Shared DX-002 verdict→Finding mapping, used by both the container and serverless passes.

    ``la is None`` (no Log Analytics provider) abstains with the ``la_unavailable`` flag so the report's
    consolidated "enable Log Analytics" guardrail picks it up.
    """
    if la is None:
        return Finding(
            detection_id="DX-002", title="Cross-partition query fan-out", unit=unit,
            status=STATUS_ABSTAINED, severity="none",
            summary="Insufficient data: Log Analytics not configured",
            recommended_action="", agent_kit_rule=None, threshold_status=THRESHOLD_VALIDATED,
            evidence={"abstained": "no Log Analytics provider", "la_unavailable": True},
        )
    v = cpq.detect_cross_partition_queries(la, account_resource_id, database, container, window)
    if v.root_cause in ("log_analytics_unavailable", "insufficient_data"):
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', v.root_cause)}"
    elif v.is_cross_partition:
        status = STATUS_FINDING
        summary = (f"{v.cross_partition_pct:.0f}% of queries fan out across ~{v.container_partitions} "
                   f"partitions at ~{v.fanout_queries_per_sec:.2f} fan-out queries/s "
                   f"(worst shape averages {v.worst_shape_fanout:.1f})")
    elif v.root_cause == "single_partition_container":
        status, summary = STATUS_NOT_DETECTED, "Single-partition container — queries cannot fan out"
    elif v.root_cause == "occasional_fanout":
        status = STATUS_NOT_DETECTED
        summary = (f"{v.cross_partition_pct:.0f}% of queries fan out, but only occasionally "
                   f"(~{v.fanout_queries_per_sec:.2f}/s) — normal cross-partition use")
    else:
        status, summary = STATUS_NOT_DETECTED, "Queries are partition-scoped"
    return Finding(
        detection_id="DX-002", title="Cross-partition query fan-out", unit=unit, status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="query-avoid-cross-partition" if v.is_cross_partition else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


def _run_dx002(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    return _dx002_finding(
        ctx.la, ctx.account_resource_id, o.database, o.container,
        ctx.window_for(cpq.production_window(ctx.now)), _unit(ctx),
    )


# --- DX-007: shard-key misalignment (structural escalation of DX-002; container + serverless) ----

def _shardkey_finding(
    la, account_resource_id: str, database: str, container: str, window, unit: UnitRef,
) -> Finding:
    """Shared DX-007 verdict→Finding mapping (container and serverless passes)."""
    if la is None:
        return Finding(
            detection_id="DX-007", title="Shard-key misalignment", unit=unit,
            status=STATUS_ABSTAINED, severity="none",
            summary="Insufficient data: Log Analytics not configured",
            recommended_action="", agent_kit_rule=None, threshold_status=THRESHOLD_VALIDATED,
            evidence={"abstained": "no Log Analytics provider", "la_unavailable": True},
        )
    v = skm.detect_shard_key_misalignment(la, account_resource_id, database, container, window)
    if v.root_cause in ("log_analytics_unavailable", "insufficient_data"):
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', v.root_cause)}"
    elif v.is_misaligned:
        status = STATUS_FINDING
        summary = (f"{v.cross_partition_pct:.0f}% of queries fan out across ~{v.container_partitions} "
                   f"partitions at ~{v.fanout_queries_per_sec:.2f} fan-out queries/s — the partition "
                   f"key is structurally misaligned (re-key)")
    else:
        status = STATUS_NOT_DETECTED
        summary = "Partition key aligned with the workload (no sustained dominant cross-partition fan-out)"
    return Finding(
        detection_id="DX-007", title="Shard-key misalignment", unit=unit, status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="partition-rekey-migration" if v.is_misaligned else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


def _run_dx007(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    return _shardkey_finding(
        ctx.la, ctx.account_resource_id, o.database, o.container,
        ctx.window_for(skm.production_window(ctx.now)), _unit(ctx),
    )


# --- DX-010: uncontrolled ingestion / burst writes (container-scoped, Log Analytics) --

def _run_dx010(ctx: DetectionContext) -> Finding:
    unit = _unit(ctx)
    o = ctx.offer
    if ctx.la is None:
        return Finding(
            detection_id="DX-010", title="Uncontrolled ingestion", unit=unit,
            status=STATUS_ABSTAINED, severity="none",
            summary="Insufficient data: Log Analytics not configured",
            recommended_action="", agent_kit_rule=None, threshold_status=THRESHOLD_VALIDATED,
            evidence={"abstained": "no Log Analytics provider", "la_unavailable": True},
        )
    if ctx.dataplane_source is None:
        raise ValueError("No request-log source was selected for DX-010.")
    v = ui.detect_uncontrolled_ingestion(
        ctx.la, ctx.account_resource_id, o.database, o.container,
        ctx.window_for(ui.production_window(ctx.now, ctx.dataplane_source)),
        source=ctx.dataplane_source,
    )
    if v.root_cause in ("log_analytics_unavailable", "insufficient_data", "query_error"):
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', v.root_cause)}"
    elif v.is_uncontrolled:
        status = STATUS_FINDING
        summary = (f"Write-dominant ({v.write_ru_pct:.0f}% of RU) and throttling at "
                   f"{v.throttle_rate_pct:.0f}% — uncontrolled ingestion (rate-control)")
    else:
        status = STATUS_NOT_DETECTED
        summary = (f"Ingestion controlled ({v.write_ru_pct:.0f}% write RU, "
                   f"{v.throttle_rate_pct:.1f}% throttling)")
    return Finding(
        detection_id="DX-010", title="Uncontrolled ingestion", unit=unit, status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="sdk-ingestion-rate-control" if v.is_uncontrolled else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


# --- DX-001: manual over-provisioning -------------------------------------------------

def _run_dx001(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = op.detect_over_provisioning(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        ctx.window_for(op.production_window()),
        scope_provisioned_ru=ctx.scope_provisioned_ru, resource_created_at=ctx.created_at(),
    )
    recoverable = v.wasted_ru if v.is_over_provisioned else None
    sav = _savings_fields(ctx, recoverable)
    if v.band == "insufficient_data":
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {v.methodology.get('abstained', '')}"
    elif v.is_over_provisioned:
        status = STATUS_FINDING
        summary = (f"{v.band} utilization (p99 {v.trigger_pct:.1f}% of {o.provisioned_ru:.0f} RU/s); "
                   f"~{v.wasted_ru:.0f} RU/s recoverable by right-sizing")
    else:
        status, summary = STATUS_NOT_DETECTED, f"Utilization healthy (p99 {v.trigger_pct:.1f}%)"
    action = (f"Right-size {o.provisioned_ru:.0f} -> {v.recommended_ru:.0f} RU/s"
              if v.is_over_provisioned else "")
    return Finding(
        detection_id="DX-001", title="Manual over-provisioning", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=action,
        agent_kit_rule="throughput-right-size" if v.is_over_provisioned else None,
        threshold_status=THRESHOLD_VALIDATED,
        recoverable_ru=recoverable,
        materiality_pct=v.materiality_pct,
        estimated_monthly_savings=sav.get("estimated_monthly_savings"),
        savings_currency=sav.get("savings_currency"),
        savings_basis=sav.get("savings_basis"),
        evidence={**v.methodology, "band": v.band, "trigger_pct": v.trigger_pct,
                  **sav.get("evidence", {})},
    )


# --- DX-004: idle container -----------------------------------------------------------

def _run_dx004(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = idle.detect_idle(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o,
        ctx.window_for(idle.production_window()),
        scope_provisioned_ru=ctx.scope_provisioned_ru, resource_created_at=ctx.created_at(),
    )
    recoverable = v.recoverable_ru if v.is_idle else None
    sav = _savings_fields(ctx, recoverable)
    if v.root_cause == "insufficient_data":
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {v.methodology.get('abstained', '')}"
    elif v.is_idle:
        status = STATUS_FINDING
        summary = (f"Idle (peak ~{v.peak_ru:.0f} RU/5min in window); "
                   f"~{v.recoverable_ru:.0f} RU/s recoverable by decommission")
    else:
        status, summary = STATUS_NOT_DETECTED, f"Active (peak ~{v.peak_ru:.0f} RU/5min in window)"
    return Finding(
        detection_id="DX-004", title="Idle container", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="throughput-idle-container-review" if v.is_idle else None,
        threshold_status=THRESHOLD_VALIDATED,
        recoverable_ru=recoverable,
        materiality_pct=v.materiality_pct,
        estimated_monthly_savings=sav.get("estimated_monthly_savings"),
        savings_currency=sav.get("savings_currency"),
        savings_basis=sav.get("savings_basis"),
        evidence={**v.methodology, **sav.get("evidence", {})},
    )


# --- DX-005: under-provisioning / throttling ------------------------------------------

def _run_dx005(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = up.detect_under_provisioning(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o,
        ctx.window_for(up.production_window()), resource_created_at=ctx.created_at(),
    )
    if v.root_cause == "insufficient_data":
        status, summary, rule = STATUS_ABSTAINED, \
            f"Insufficient data: {v.methodology.get('abstained', '')}", None
    elif v.is_under_provisioned:
        status = STATUS_FINDING
        summary = f"Throttling {v.throttle_rate_pct:.1f}% with all partitions saturated"
        rule = "throughput-autoscale" if o.mode == "autoscale" else "throughput-right-size"
    elif v.root_cause == "skew_suspected":
        # Skew is DX-006's domain — DX-005 reports no *global* under-provisioning here.
        status = STATUS_NOT_DETECTED
        summary = f"Throttling {v.throttle_rate_pct:.1f}% is partition-skewed — see DX-006"
        rule = None
    else:
        status, summary, rule = STATUS_NOT_DETECTED, "No sustained throttling", None
    return Finding(
        detection_id="DX-005", title="Under-provisioning / throttling", unit=_unit(ctx),
        status=status, severity=v.severity, summary=summary,
        recommended_action=v.recommended_action, agent_kit_rule=rule,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


# --- DX-006: hot partition ------------------------------------------------------------

def _run_dx006(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = hp.detect_hot_partition(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o,
        ctx.window_for(hp.production_window()), resource_created_at=ctx.created_at(),
    )
    if v.root_cause == "insufficient_data":
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', 'no per-partition data')}"
    elif v.is_hot_partition:
        status = STATUS_FINDING
        warn = "throttling" if v.throttling else "saturated, not throttling yet (early warning)"
        summary = (f"Hot partition: busiest p99 {v.max_p99:.0f}% vs coolest {v.min_p99:.0f}% "
                   f"across {v.partition_count} partitions ({warn})")
    else:
        status, summary = STATUS_NOT_DETECTED, "Partition load is balanced"
    return Finding(
        detection_id="DX-006", title="Hot partition", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="partition-high-cardinality" if v.is_hot_partition else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


# --- DX-015: partition storage skew ---------------------------------------------------

def _run_dx015(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = ss.detect_storage_skew(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o,
        ctx.window_for(ss.production_window()), resource_created_at=ctx.created_at(),
    )
    gib = 1024**3
    if v.root_cause == "insufficient_data":
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', 'no per-partition storage')}"
    elif v.is_storage_skew:
        status = STATUS_FINDING
        summary = (f"Storage skew: busiest partition {v.max_bytes / gib:.1f} GiB "
                   f"({v.busiest_pct_of_limit:.0f}% of the 50 GiB limit) vs coolest "
                   f"{v.min_bytes / gib:.1f} GiB across {v.partition_count} partitions")
    else:
        status, summary = STATUS_NOT_DETECTED, "Storage is evenly distributed across partitions"
    return Finding(
        detection_id="DX-015", title="Partition storage skew", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="partition-high-cardinality" if v.is_storage_skew else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


# --- DX-011: autoscale maximum right-sizing -----------------------------------------

def _run_dx011(ctx: DetectionContext) -> Finding:
    """Keep the utilization finding while distinguishing analytical reductions from no-op targets."""
    o = ctx.offer
    v = asig.detect_autoscale_max_over_provisioned(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        ctx.window_for(op.production_window()),
        scope_provisioned_ru=ctx.scope_provisioned_ru, resource_created_at=ctx.created_at(),
    )
    recoverable = v.wasted_ru if v.is_over_provisioned else None
    sav = _savings_fields(ctx, recoverable)
    if v.band == "insufficient_data":
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {v.methodology.get('abstained', '')}"
    elif v.is_over_provisioned:
        status = STATUS_FINDING
        if v.recommended_ru < o.provisioned_ru:
            summary = (f"Autoscale max set too high (peak provisioned {v.trigger_pct:.1f}% of "
                       f"{o.provisioned_ru:.0f} RU/s max); ~{v.wasted_ru:.0f} RU/s recoverable by "
                       f"lowering the max")
        else:
            summary = (f"Autoscale max is at the modeled minimum "
                       f"(peak provisioned {v.trigger_pct:.1f}% of max); no reduction is available")
    else:
        status = STATUS_NOT_DETECTED
        summary = f"Autoscale max is appropriate (peak provisioned {v.trigger_pct:.1f}% of max)"
    action = ""
    if v.is_over_provisioned:
        action = (
            f"Review lowering the autoscale max {o.provisioned_ru:.0f} -> "
            f"{v.recommended_ru:.0f} RU/s (analytical target). "
            if v.recommended_ru < o.provisioned_ru else
            "The autoscale maximum is already at the modeled minimum; no reduction is available. "
        )
        action += (
            "Validate service increments and resource-specific minimum maxima before changing "
            "configuration; the model does not establish service eligibility."
        )
    return Finding(
        detection_id="DX-011", title="Autoscale max over-provisioned", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=action,
        agent_kit_rule="throughput-right-size" if v.is_over_provisioned else None,
        threshold_status=THRESHOLD_VALIDATED,
        recoverable_ru=recoverable,
        materiality_pct=v.materiality_pct,
        estimated_monthly_savings=sav.get("estimated_monthly_savings"),
        savings_currency=sav.get("savings_currency"),
        savings_basis=sav.get("savings_basis"),
        evidence={**v.methodology, "band": v.band, "trigger_pct": v.trigger_pct,
                  **sav.get("evidence", {})},
    )


def _run_dx013(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = ms.detect_autoscale_to_manual(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        ctx.window_for(op.production_window()), resource_created_at=ctx.created_at(),
    )
    if v.root_cause == "insufficient_data":
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {v.methodology.get('abstained', '')}"
    elif v.recommend_switch:
        status = STATUS_FINDING
        summary = (f"Steady-high load (autoscale sat at average {v.avg:.0f}% of max, little "
                   f"spikiness) — manual would avoid the autoscale premium")
    else:
        status, summary = STATUS_NOT_DETECTED, "Load shape benefits from autoscale"
    return Finding(
        detection_id="DX-013", title="Autoscale to manual candidate", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="throughput-right-size" if v.recommend_switch else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


# --- DX-012: manual -> autoscale candidate (spiky duty cycle) -------------------------

def _run_dx012(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = ms.detect_manual_to_autoscale(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        ctx.window_for(op.production_window()), resource_created_at=ctx.created_at(),
    )
    if v.root_cause == "insufficient_data":
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {v.methodology.get('abstained', '')}"
    elif v.recommend_switch:
        status = STATUS_FINDING
        summary = (f"Bursty load (peak {v.max_util:.0f}% vs average {v.avg:.0f}%, "
                   f"{v.peak_to_avg:.0f}x) — autoscale would cut idle-time cost while covering peaks")
    else:
        status, summary = STATUS_NOT_DETECTED, "Load shape is well matched to manual throughput"
    return Finding(
        detection_id="DX-012", title="Manual to autoscale candidate", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="throughput-autoscale" if v.recommend_switch else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


# --- DX-009: partition merge candidate (over-partitioned) -----------------------------

def _run_dx009(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    # PhysicalPartitionCount supports only a 5-minute grain, so DX-009 uses its own recent window
    # (partition count is slow-moving state) regardless of the run mode.
    v = pm.detect_partition_merge(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        pm.recent_window(),
        account_config=ctx.account_config,
    )
    if v.root_cause == "insufficient_data":
        status, summary = STATUS_ABSTAINED, "Insufficient data: no partition-count telemetry"
    elif v.is_over_partitioned:
        status = STATUS_FINDING
        summary = (f"Over-partitioned: {v.actual_partitions} physical partitions but only "
                   f"{v.needed_partitions} needed (~{v.ru_per_partition:.0f} RU/s each)")
        eligibility = v.methodology["merge_eligibility"]
        if eligibility == "blocked_pitr":
            summary += "; partition merge blocked by continuous backup (PITR)"
        elif eligibility == "blocked_full_fidelity":
            summary += "; partition merge blocked by enabled full-fidelity change feed"
        elif eligibility == "unknown":
            summary += "; merge eligibility unverified"
        else:
            summary += "; merge requires platform eligibility checks"
    else:
        status, summary = STATUS_NOT_DETECTED, f"Partition count is appropriate ({v.actual_partitions})"
    return Finding(
        detection_id="DX-009", title="Partition merge candidate", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule=None,  # merge is a platform (Portal/CLI) operation, no code remediation
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


# --- DX-017: rapid storage growth -----------------------------------------------------

def _run_dx017(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = sg.detect_storage_growth(
        ctx.metrics, ctx.account_resource_id, o.database, o.container,
        ctx.window_for(sg.production_window()),
    )
    if v.root_cause == "insufficient_data":
        status, summary = STATUS_ABSTAINED, "Insufficient data: no per-partition storage telemetry"
    elif v.is_rapid_growth:
        status = STATUS_FINDING
        summary = (f"Storage growing ~{v.growth_rate_gib_per_day:.2f} GiB/day "
                   f"(busiest partition {v.busiest_current_gib:.1f} GiB) — ~{v.days_to_limit:.0f} "
                   f"days to the 50 GiB limit")
    else:
        status, summary = STATUS_NOT_DETECTED, "Storage growth is within a safe horizon"
    return Finding(
        detection_id="DX-017", title="Rapid storage growth", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="throughput-ttl-stale-data" if v.is_rapid_growth else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


REGISTRY: list[DetectionAdapter] = [
    DetectionAdapter("DX-001", "Manual over-provisioning",
                     lambda o: _is_metrics_scoped(o) and o.mode == "manual", _run_dx001),
    DetectionAdapter("DX-002", "Cross-partition query fan-out", _is_container, _run_dx002,
                     requires=frozenset({CAP_LA_QUERYSTATS, CAP_LA_DATAPLANE})),
    DetectionAdapter("DX-007", "Shard-key misalignment", _is_container, _run_dx007,
                     requires=frozenset({CAP_LA_QUERYSTATS, CAP_LA_DATAPLANE})),
    DetectionAdapter("DX-010", "Uncontrolled ingestion", _is_container, _run_dx010,
                     requires=frozenset({CAP_LA_REQUEST_AGGREGATES})),
    DetectionAdapter("DX-004", "Idle container", _is_metrics_scoped, _run_dx004),
    DetectionAdapter("DX-005", "Under-provisioning / throttling", _is_metrics_scoped, _run_dx005),
    DetectionAdapter("DX-006", "Hot partition", _is_metrics_scoped, _run_dx006),
    DetectionAdapter("DX-015", "Partition storage skew", _is_container, _run_dx015),
    DetectionAdapter("DX-011", "Autoscale max over-provisioned",
                     lambda o: _is_metrics_scoped(o) and o.mode == "autoscale", _run_dx011),
    DetectionAdapter("DX-012", "Manual to autoscale candidate",
                     lambda o: _is_container(o) and o.mode == "manual", _run_dx012),
    DetectionAdapter("DX-013", "Autoscale to manual candidate",
                     lambda o: _is_container(o) and o.mode == "autoscale", _run_dx013),
    DetectionAdapter("DX-009", "Partition merge candidate", _is_container, _run_dx009),
    DetectionAdapter("DX-017", "Rapid storage growth", _is_container, _run_dx017),
]


# --- DX-008: multi-region writes antipattern (account-scoped) -------------------------

def _run_dx008(ctx: AccountDetectionContext) -> Finding:
    v = mrw.detect_multi_region_writes(ctx.config, ctx.throughput_offers)
    capacity = v.methodology.get("regional_capacity", {})
    removable = capacity.get("removable_extra_region_ru") if isinstance(capacity, dict) else None
    savings = (
        _savings_fields(ctx, removable)
        if v.is_antipattern
        and isinstance(capacity, dict)
        and capacity.get("status") == "quantified"
        and _is_positive_finite(removable)
        else {}
    )
    if v.is_antipattern:
        status = STATUS_FINDING
        summary = _dx008_summary(
            v,
            estimated_monthly_savings=savings.get("estimated_monthly_savings"),
            savings_currency=savings.get("savings_currency"),
        )
    elif v.root_cause == "legitimate_ha":
        status = STATUS_NOT_DETECTED
        summary = "Multi-region writes on a production account — treated as intentional RTO=0 HA"
    else:
        status, summary = STATUS_NOT_DETECTED, "Multi-region writes are not enabled"
    return Finding(
        detection_id="DX-008", title="Multi-region writes antipattern", unit=_account_unit(ctx),
        status=status, severity=v.severity, summary=summary,
        recommended_action=v.recommended_action,
        agent_kit_rule="global-multi-region-write-antipattern" if v.is_antipattern else None,
        threshold_status=THRESHOLD_VALIDATED,
        estimated_monthly_savings=savings.get("estimated_monthly_savings"),
        savings_currency=savings.get("savings_currency"),
        savings_basis=savings.get("savings_basis"),
        evidence={**v.methodology, **savings.get("evidence", {})},
    )


def _dx008_summary(
    v: mrw.MultiRegionWriteVerdict,
    *,
    estimated_monthly_savings: float | None = None,
    savings_currency: str | None = None,
) -> str:
    """Summarize DX-008 with bill-derived savings first and regional capacity as context."""
    capacity = v.methodology["regional_capacity"]
    if v.root_cause == "mongo_multi_region_writes":
        summary = "Multi-region writes on a MongoDB API account (drivers can't use the write failover)"
    elif v.root_cause.endswith("_multi_region_writes") and v.root_cause != "nonprod_multi_region_writes":
        summary = "Multi-region writes on an API whose drivers cannot use the write failover"
    elif v.root_cause == "nonprod_multi_region_writes":
        summary = (
            f"Multi-region writes across {v.write_region_count} write regions on a "
            "non-production account (no RTO=0 need)"
        )
    else:
        summary = "Multi-region writes enabled on a single-region account (latent tripwire)"
    if (
        capacity["status"] == "quantified"
        and _is_positive_finite(capacity.get("configured_per_region_ru"))
        and _is_positive_finite(capacity.get("global_regional_ru"))
    ):
        summary += (
            f"; {capacity['configured_per_region_ru']:,.0f} RU/s per region yields "
            f"{capacity['global_regional_ru']:,.0f} regional RU/s globally"
        )
        removable = capacity["removable_extra_region_ru"]
        if _is_positive_finite(removable):
            summary += (
                f", with {removable:,.0f} regional RU/s removable only by removing "
                "the unnecessary extra region(s)"
            )
    if (
        _is_positive_finite(estimated_monthly_savings)
        and isinstance(savings_currency, str)
        and savings_currency.strip()
    ):
        summary = (
            "Estimated monthly savings from your amortized bill: "
            f"~{estimated_monthly_savings:,.2f} {savings_currency}/month; {summary}"
        )
    return summary


# --- DX-016: expensive consistency (account-scoped) -----------------------------------

def _run_dx016(ctx: AccountDetectionContext) -> Finding:
    """Preserve the ARM finding and separate read-RU trade-offs from optional log observations."""
    v = cons.detect_expensive_consistency(ctx.config)
    evidence = dict(v.methodology)
    if v.is_expensive:
        status = STATUS_FINDING
        summary = (
            f"{v.consistency_level} consistency in 1 region — local quorum reads can cost twice "
            "the read RU of Session"
            if v.region_count == 1 else
            f"{v.consistency_level} consistency across {v.region_count} regions — higher read RU "
            "and cross-region latency/availability trade-offs"
        )
        window = ctx.window_for(cons.production_window(ctx.now))
        if ctx.dataplane_source is not None:
            window = ctx.window_for(cons.production_window(ctx.now, ctx.dataplane_source))
        if ctx.la is None:
            evidence["read_ru_enrichment"] = {
                "status": "unavailable",
                "reason": "log_analytics_provider_not_configured",
                "observation_window": {
                    "start_utc": window.start.isoformat(),
                    "end_utc": window.end.isoformat(),
                    "semantics": "[start,end)",
                },
            }
        elif ctx.dataplane_source is None:
            evidence["read_ru_enrichment"] = {
                "status": "unavailable",
                "reason": ctx.dataplane_error or "request_log_source_unavailable",
                "observation_window": {
                    "start_utc": window.start.isoformat(),
                    "end_utc": window.end.isoformat(),
                    "semantics": "[start,end)",
                },
            }
        else:
            try:
                read_ru = cons.observe_read_request_charge(
                    ctx.la,
                    ctx.account_resource_id,
                    window,
                    source=ctx.dataplane_source,
                )
                evidence["read_ru_enrichment"] = read_ru
                if read_ru["status"] == "observed":
                    summary += (
                        f"; observed {read_ru['observed_read_request_charge_ru']:,.2f} read RU in "
                        f"[{window.start.isoformat()}, {window.end.isoformat()}), with "
                        f"{read_ru['upper_bound_avoidable_read_request_charge_ru']:,.2f} RU as an "
                        "upper-bound avoidable charge"
                    )
            except Exception as exc:  # noqa: BLE001 - optional enrichment cannot suppress ARM finding
                evidence["read_ru_enrichment"] = {
                    "status": "unavailable",
                    "reason": f"{type(exc).__name__}: {str(exc)[:200]}",
                    "observation_window": {
                        "start_utc": window.start.isoformat(),
                        "end_utc": window.end.isoformat(),
                        "semantics": "[start,end)",
                    },
                }
    else:
        status, summary = STATUS_NOT_DETECTED, f"Consistency level is appropriate ({v.consistency_level})"
    return Finding(
        detection_id="DX-016", title="Expensive consistency", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="global-consistency" if v.is_expensive else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=evidence,
    )


# --- DX-019: PITR (continuous backup) on a non-production account (account-scoped) -----


def _dx019_savings_fields(ctx: AccountDetectionContext) -> dict:
    """Build strictly evidenced list-price savings fields for a paid DX-019 finding."""
    if ctx.arm is None:
        raise ValueError("ARM provider unavailable")
    if ctx.retail_prices is None:
        raise ValueError("Retail Prices provider unavailable")
    if not ctx.config.location_names:
        raise ValueError("account has no configured regions")

    expected = tuple(ctx.arm.list_containers(ctx.resource_group, ctx.account))
    canonical_regions = ctx.arm.resolve_arm_region_names(ctx.config.location_names)
    reference_region = ctx.config.location_names[0]
    metric_window = TimeWindow(
        ctx.now - timedelta(hours=24),
        ctx.now,
        timedelta(minutes=5),
    )
    samples = ctx.metrics.get_data_usage_v2_samples(
        ctx.account_resource_id,
        metric_window,
        reference_region=reference_region,
    )
    snapshot = select_complete_storage_snapshot(
        samples,
        expected,
        reference_region,
        ctx.now,
    )
    prices = ctx.retail_prices.pitr_storage_prices(canonical_regions, as_of=ctx.now)
    currencies = {price.currency for price in prices}
    if len(currencies) != 1:
        raise ValueError("Retail Prices returned mixed currencies")
    currency = next(iter(currencies))
    regional_rate = sum(price.rate_per_gb_month for price in prices)
    amount = round(snapshot.decimal_gb * regional_rate, 2)
    return {
        "estimated_monthly_savings": amount,
        "savings_currency": currency,
        "savings_basis": "azure_retail_price",
        "evidence": {
            "storage_snapshot": {
                "metric": "DataUsageV2",
                "timestamp": snapshot.timestamp.isoformat(),
                "reference_region": snapshot.reference_region,
                "logical_containers": snapshot.logical_containers,
                "total_bytes": snapshot.total_bytes,
                "logical_storage_gb": snapshot.decimal_gb,
                "gb_conversion": "decimal",
                "bytes_per_gb": 1_000_000_000,
            },
            "retail_pricing": {
                "source": RETAIL_PRICES_BASE_URL,
                "meter_name": PITR_STORAGE_METER_NAME,
                "unit_of_measure": PITR_UNIT,
                "currency": currency,
                "regions": [
                    {
                        "arm_region_name": price.arm_region_name,
                        "rate_per_gb_month": price.rate_per_gb_month,
                        "meter_id": price.meter_id,
                        "effective_start_date": price.effective_start_date,
                        "effective_end_date": price.effective_end_date,
                    }
                    for price in prices
                ],
                "sum_per_region_rate_per_gb_month": regional_rate,
            },
            "formula": (
                "logical_storage_gb_decimal * sum(per_region_current_storage_rate_per_gb_month)"
            ),
            "restore_charges_included": False,
        },
    }


def _run_dx019(ctx: AccountDetectionContext) -> Finding:
    v = pitr.detect_pitr_on_nonprod(ctx.config)
    savings: dict = {}
    evidence = dict(v.methodology)
    evidence["root_cause"] = v.root_cause
    if v.is_antipattern:
        status = STATUS_FINDING
        summary = (f"Continuous backup / PITR ({v.continuous_backup_tier or 'continuous'}) on a "
                   f"non-production account — paid backup-storage tier may be unnecessary")
        try:
            savings = _dx019_savings_fields(ctx)
            evidence.update(savings.pop("evidence"))
        except Exception as exc:  # noqa: BLE001 - enrichment must never suppress the qualitative finding
            evidence["savings_enrichment"] = {
                "status": "unavailable",
                "reason": f"{type(exc).__name__}: {str(exc)[:200]}",
            }
    elif v.root_cause == "legitimate_prod_backup":
        status, summary = STATUS_NOT_DETECTED, "Continuous backup on a production account (legitimate)"
    elif v.root_cause == "uncharged_7day_backup":
        status = STATUS_NOT_DETECTED
        summary = (
            "Continuous7Days has no backup-storage charge; restore operations are charged separately"
        )
    elif v.root_cause == "unknown_continuous_tier":
        status = STATUS_ABSTAINED
        summary = (
            "Insufficient data: continuous backup tier is missing or unrecognized; "
            "backup-storage cost not asserted"
        )
    elif v.root_cause == "unknown":
        status, summary = STATUS_ABSTAINED, "Insufficient data: backup policy not reported by ARM"
    else:
        status, summary = STATUS_NOT_DETECTED, "Periodic backup"
    return Finding(
        detection_id="DX-019", title="PITR on non-prod", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule=None, threshold_status=threshold_status_for("DX-019"), evidence=evidence,
        **savings,
    )


# --- DX-020: non-throttling error-code analysis (account-scoped, metrics only) ---------

def _run_dx020(ctx: AccountDetectionContext) -> Finding:
    """Translate unchanged status-only detection into conditional investigation guidance."""
    window = ctx.window_for(ea.production_window())
    series = ctx.metrics.get_metric_split(
        ctx.account_resource_id, "TotalRequests", window,
        split_dimension="StatusCode", aggregation="Count",
    )
    counts = {code: int(sum(s.values())) for code, s in series.items()}
    v = ea.detect_error_patterns(counts)
    if v.root_cause == "too_few_requests":
        status, summary = STATUS_ABSTAINED, "Insufficient data: not enough requests to judge error rate"
    elif v.is_finding:
        status = STATUS_FINDING
        summary = (f"{v.hard_error_rate_pct:.1f}% non-throttling errors "
                   f"(top: HTTP {v.dominant_code} at {v.dominant_rate_pct:.1f}%)")
    else:
        status, summary = STATUS_NOT_DETECTED, "No material non-throttling error pattern"
    return Finding(
        detection_id="DX-020", title="Error-code analysis", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule=dx020_agent_kit_rule(status, v.dominant_code),
        threshold_status=threshold_status_for("DX-020"), evidence=v.methodology,
    )


# --- DX-021: throttling root-cause decomposition (account-scoped, metrics only) --------

def _run_dx021(ctx: AccountDetectionContext) -> Finding:
    window = ctx.window_for(trc.production_window())
    by_code = ctx.metrics.get_metric_split(
        ctx.account_resource_id, "TotalRequests", window,
        split_dimension="StatusCode", aggregation="Count",
    )
    code_counts = {code: int(sum(s.values())) for code, s in by_code.items()}
    total_requests = sum(code_counts.values())
    total_throttled = code_counts.get("429", 0)
    by_op = ctx.metrics.get_metric_split(
        ctx.account_resource_id, "TotalRequests", window,
        split_dimension="OperationType", dimension_filter={"StatusCode": "429"}, aggregation="Count",
    )
    op_throttled = {op: int(sum(s.values())) for op, s in by_op.items()}
    v = trc.detect_throttling_root_cause(total_requests, total_throttled, op_throttled)
    if v.root_cause == "too_few_requests":
        status, summary = STATUS_ABSTAINED, "Insufficient data: not enough requests to decompose throttling"
    elif v.is_finding:
        status = STATUS_FINDING
        summary = (f"{v.throttle_rate_pct:.1f}% throttled; {v.dominant_share_pct:.0f}% on "
                   f"'{v.dominant_operation}' ({v.dominant_category})")
    else:
        status, summary = STATUS_NOT_DETECTED, "No material throttling to decompose"
    return Finding(
        detection_id="DX-021", title="Throttling root cause", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule=dx021_agent_kit_rule(status, v.dominant_category),
        threshold_status=threshold_status_for("DX-021"), evidence=v.methodology,
    )


# --- DX-022: Per-Region Provisioned Autoscale opportunity (account-scoped, ARM) --------

def _run_dx022(ctx: AccountDetectionContext) -> Finding:
    v = prpa.detect_prpa_candidate(ctx.config)
    if v.is_candidate:
        status = STATUS_FINDING
        summary = f"Multi-region ({v.region_count} regions) without PRPA — evaluate per-region autoscale"
    else:
        summary = {
            "single_region": "Single region — PRPA not applicable",
            "already_enabled": "PRPA already enabled",
            "serverless": "Serverless — no provisioned per-region autoscale",
        }.get(v.root_cause, "Not a PRPA candidate")
        status = STATUS_NOT_DETECTED
    return Finding(
        detection_id="DX-022", title="PRPA opportunity", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule=None, threshold_status=threshold_status_for("DX-022"), evidence=v.methodology,
    )


# --- DX-023: Reserved Capacity opportunity (account-scoped) ----------------------------

def _run_dx023(ctx: AccountDetectionContext) -> Finding:
    v = rc.detect_reserved_capacity_candidate(
        ctx.scope_provisioned_ru, is_serverless=ctx.config.is_serverless,
    )
    if v.is_candidate:
        status = STATUS_FINDING
        summary = f"~{v.provisioned_ru:,.0f} RU/s provisioned baseline — evaluate reserved capacity"
    elif v.root_cause == "unknown":
        status, summary = STATUS_ABSTAINED, "Insufficient data: provisioned throughput unknown"
    else:
        summary = {
            "serverless": "Serverless — nothing provisioned to reserve",
            "below_baseline": "Provisioned baseline below the reserved-capacity floor",
        }.get(v.root_cause, "Not a reserved-capacity candidate")
        status = STATUS_NOT_DETECTED
    return Finding(
        detection_id="DX-023", title="Reserved capacity", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule=None, threshold_status=threshold_status_for("DX-023"), evidence=v.methodology,
    )


# --- DX-014: provisioned -> serverless candidate (account-scoped) ----------------------

def _run_dx014(ctx: AccountDetectionContext) -> Finding:
    v = svc.detect_serverless_candidate(
        ctx.metrics, ctx.account_resource_id, ctx.window_for(svc.production_window()),
        is_serverless=ctx.config.is_serverless,
    )
    if v.root_cause == "already_serverless":
        status, summary = STATUS_NOT_DETECTED, "Account is already serverless"
    elif v.root_cause == "insufficient_data":
        status, summary = STATUS_ABSTAINED, "Insufficient data: not enough consumed-RU history"
    elif v.is_candidate:
        status = STATUS_FINDING
        summary = (f"Low, sporadic throughput (peak {v.peak_ru_per_s:.0f} RU/s, "
                   f"{v.avg_to_peak * 100:.0f}% avg-to-peak) — evaluate serverless")
    else:
        status, summary = STATUS_NOT_DETECTED, "Throughput shape does not fit serverless"
    return Finding(
        detection_id="DX-014", title="Serverless candidate", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="throughput-serverless-migration" if v.is_candidate else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


ACCOUNT_REGISTRY: list[AccountDetectionAdapter] = [
    AccountDetectionAdapter("DX-008", "Multi-region writes antipattern", _run_dx008),
    AccountDetectionAdapter(
        "DX-016", "Expensive consistency", _run_dx016,
        optional_requires=frozenset({CAP_LA_REQUEST_AGGREGATES}),
    ),
    AccountDetectionAdapter("DX-014", "Serverless candidate", _run_dx014),
    AccountDetectionAdapter("DX-019", "PITR on non-prod", _run_dx019),
    AccountDetectionAdapter("DX-020", "Error-code analysis", _run_dx020),
    AccountDetectionAdapter("DX-021", "Throttling root cause", _run_dx021),
    AccountDetectionAdapter("DX-022", "PRPA opportunity", _run_dx022),
    AccountDetectionAdapter("DX-023", "Reserved capacity", _run_dx023),
]


# --- DX-003: shared-throughput starvation (database-scoped, Log Analytics) -------------

def _run_dx003(ctx: DatabaseDetectionContext) -> Finding:
    if ctx.dataplane_source is None:
        raise ValueError("No request-log source was selected for DX-003.")
    win = ctx.window_for(sht.production_window(ctx.now, ctx.dataplane_source))
    v = sht.detect_shared_throughput_starvation(
        ctx.la, ctx.account_resource_id, ctx.database, ctx.shared_ru, win,
        source=ctx.dataplane_source,
    )
    if v.root_cause in ("log_analytics_unavailable", "insufficient_data", "query_error"):
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', v.root_cause)}"
    elif v.is_starvation:
        status = STATUS_FINDING
        summary = (f"Starvation in shared DB '{v.database}': '{v.monopolizer}' consumes "
                   f"{v.monopolizer_ru_share_pct:.0f}% of the pool while '{v.victim}' throttles at "
                   f"{v.victim_throttle_rate_pct:.0f}%")
    else:
        status = STATUS_NOT_DETECTED
        summary = (f"Shared pool healthy (DB 429 rate {v.pool_throttle_rate_pct:.1f}%, "
                   f"{v.collection_count} collections)")
    return Finding(
        detection_id="DX-003", title="Shared-throughput starvation", unit=_database_unit(ctx),
        status=status, severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="throughput-container-vs-database" if v.is_starvation else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


DATABASE_REGISTRY: list[DatabaseDetectionAdapter] = [
    DatabaseDetectionAdapter("DX-003", "Shared-throughput starvation", _run_dx003,
                             requires=frozenset({CAP_LA_REQUEST_AGGREGATES})),
]


# --- DX-002 on serverless containers (Log Analytics) ----------------------------------

def _run_dx002_serverless(ctx: ServerlessDetectionContext) -> Finding:
    """DX-002 on a serverless container. Serverless emits CDBQueryRuntimeStatistics, so the same
    cross-partition fan-out detection applies (verified live); it just runs on the serverless pass
    since serverless containers have no throughput offer."""
    return _dx002_finding(
        ctx.la, ctx.account_resource_id, ctx.database, ctx.container,
        ctx.window_for(cpq.production_window(ctx.now)), _serverless_unit(ctx),
    )


def _run_dx007_serverless(ctx: ServerlessDetectionContext) -> Finding:
    """DX-007 on a serverless container (same fan-out signal as the container pass)."""
    return _shardkey_finding(
        ctx.la, ctx.account_resource_id, ctx.database, ctx.container,
        ctx.window_for(skm.production_window(ctx.now)), _serverless_unit(ctx),
    )


# --- DX-018: serverless throttling (serverless-container-scoped) -----------------------

def _run_dx018(ctx: ServerlessDetectionContext) -> Finding:
    v = svt.detect_serverless_throttling(
        ctx.metrics, ctx.account_resource_id, ctx.database, ctx.container,
        ctx.window_for(svt.production_window()),
    )
    if v.root_cause == "insufficient_data":
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', v.root_cause)}"
    elif v.is_throttling:
        status = STATUS_FINDING
        summary = (f"Serverless container throttling at {v.throttle_rate_pct:.1f}% 429s "
                   f"(hitting the 5,000 RU/s per-partition ceiling; no throughput knob)")
    else:
        status = STATUS_NOT_DETECTED
        summary = f"Serverless container not throttling ({v.throttle_rate_pct:.1f}% 429s)"
    return Finding(
        detection_id="DX-018", title="Serverless throttling", unit=_serverless_unit(ctx),
        status=status, severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="throughput-serverless" if v.is_throttling else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


SERVERLESS_REGISTRY: list[ServerlessDetectionAdapter] = [
    ServerlessDetectionAdapter("DX-018", "Serverless throttling", _run_dx018),
    ServerlessDetectionAdapter("DX-002", "Cross-partition query fan-out", _run_dx002_serverless,
                               requires=frozenset({CAP_LA_QUERYSTATS, CAP_LA_DATAPLANE})),
    ServerlessDetectionAdapter("DX-007", "Shard-key misalignment", _run_dx007_serverless,
                               requires=frozenset({CAP_LA_QUERYSTATS, CAP_LA_DATAPLANE})),
]


# --- DX-024: indexing cost risk (all containers; ADR-0069) -----------------------------

def _run_dx024(ctx: InventoryDetectionContext) -> Finding:
    c = ctx.container
    v = ic.detect_indexing_cost(
        ctx.metrics, ctx.account_resource_id, c.database, c.container,
        ctx.window_for(ic.production_window(ctx.now)),
        indexing_mode=c.indexing_mode, excluded_paths=c.excluded_paths,
    )
    if v.root_cause == "insufficient_data":
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', v.root_cause)}"
    elif v.is_risk:
        status = STATUS_FINDING
        summary = (f"Index storage is {v.ratio:.0%} of data storage "
                   f"({v.user_excluded_path_count} user-excluded path(s)) — likely over-indexed")
    elif v.root_cause == "indexing_disabled":
        status, summary = STATUS_NOT_DETECTED, "Indexing is disabled (mode none)"
    else:
        status = STATUS_NOT_DETECTED
        summary = f"Index storage is {v.ratio:.0%} of data storage (within 30%)"
    return Finding(
        detection_id="DX-024", title="Indexing cost risk", unit=_inventory_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="index-exclude-unused" if v.is_risk else None,
        threshold_status=threshold_status_for("DX-024"),
        evidence={**v.methodology, "index_bytes": v.index_bytes, "data_bytes": v.data_bytes},
    )


INVENTORY_REGISTRY: list[InventoryDetectionAdapter] = [
    InventoryDetectionAdapter("DX-024", "Indexing cost risk", _run_dx024),
]

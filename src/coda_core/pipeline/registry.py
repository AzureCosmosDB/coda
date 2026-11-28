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
from dataclasses import asdict, dataclass
from datetime import timedelta


from coda_core.detections import autoscale_signal as asig
from coda_core.detections import consistency as cons
from coda_core.detections import cross_partition_query as cpq
from coda_core.detections import error_analysis as ea
from coda_core.detections import hot_partition as hp
from coda_core.detections import idle_container as idle
from coda_core.detections import indexing_cost as ic
from coda_core.detections.logical_partition_storage import LogicalStorage
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
    HOURS_PER_MONTH,
    THROUGHPUT_METER_UNIT_RU,
    RATE_SOURCE_CUSTOMER_AMORTIZED_BILL,
    billing_quantity,
    throughput_meter,
)
from coda_core.pipeline.capabilities import (
    CAP_COST_MANAGEMENT,
    CAP_LA_DATAPLANE,
    CAP_LA_KEYSTATS,
    CAP_LA_QUERYSTATS,
    CAP_LA_REQUEST_AGGREGATES,
    CAPABILITIES,
    CapabilitySet,
)
from coda_core.pipeline.context import (
    MODE_PRODUCTION,
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
from coda_core.providers.indexing_batch import IncompleteBatch
from coda_core.providers.monitor_retry import MonitorUnavailable
from coda_core.providers.base import TimeWindow
from coda_core.providers.shared_offer import IncompletePool
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
    "DX-004",  # exactly zero consumed RU across 30 measured days (definitional)
    "DX-005",  # throttle 5%/20% ≈ p25/p50 of fleet throttle dist; 90% saturation = 99.8% fleet
    "DX-006",  # shares DX-005's fleet-validated 90% saturation cutoff
    "DX-008",  # multi-region-writes config fact (deterministic)
    "DX-009",  # partition-merge: multi-partition + low RU (86% of multi-partition are ≤6000 RU)
    "DX-011",  # autoscale max over-provisioned: peak <30% of max (74% of autoscale fleet; autoscale RU telemetry)
    "DX-014",  # deterministic equal-period throughput cost comparison; no traffic-shape cutoff
    "DX-016",  # consistency-level config fact (deterministic)
    "DX-019",  # paid continuous tier + non-production config facts (deterministic)
    "DX-022",  # verified autoscale offer and explicitly disabled dynamic scaling (deterministic)
    "DX-024",  # index/data >0.3 footprint (27.5% in historical sample); not severity or savings
})

# Private campaign metadata also checks this: operation recipients alone have no prescribed fix.
DX021_AGENT_KIT_RULES: dict[str, str] = {}


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
    minimum_age: timedelta | None = None
    optional_requires: frozenset[str] = frozenset()


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
    ctx: DetectionContext,
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
        or not _is_positive_finite(rate.unit_price_per_100rus_hour)
        or not math.isclose(rate.usd_per_ru_month,
                            rate.unit_price_per_100rus_hour / THROUGHPUT_METER_UNIT_RU * HOURS_PER_MONTH,
                            rel_tol=1e-12)
        or not isinstance(rate.currency, str)
        or not rate.currency.strip()
        or not isinstance(rate.basis, dict)
        or rate.rate_scope not in APPROVED_EFFECTIVE_RATE_SCOPES
        or rate.basis.get("rate_source") != RATE_SOURCE_CUSTOMER_AMORTIZED_BILL
        or rate.basis.get("rate_scope") != rate.rate_scope
    ):
        return {}
    config = ctx.account_config
    meter = throughput_meter(config)
    if meter is None or config is None or rate.basis.get("meters") != [meter]:
        return {"evidence": {"throughput_pricing_issue": "Matching billing meter or topology unavailable"}}
    quantity = billing_quantity(config, meter, ctx.offer.mode, recoverable_ru, already_regional=False)
    if quantity is None:
        return {"evidence": {"throughput_pricing_issue":
                             "Regional billed quantity is unknown; verify offer mode and regional zone settings."}}
    amount = quantity.monthly_estimate(rate)
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
            "billing_quantity": {**asdict(quantity), "hours_per_month": HOURS_PER_MONTH,
                                 "unit_price_per_100rus_hour": rate.unit_price_per_100rus_hour},
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
    """One independent capacity allocation: a dedicated container or the shared pool (ADR-0078)."""
    return offer.level in ("container", "database")


# --- Graceful degradation: one detection's failure must never abort the whole run ------

def _error_finding(detection_id: str, title: str, unit: UnitRef, exc: Exception) -> Finding:
    """An unexpected detection error degrades to an ABSTAINED finding (not a crashed run).

    The error is captured in evidence for diagnosis; it is *not* flagged ``la_unavailable`` (so it
    doesn't wrongly trip the report's "enable Log Analytics" guardrail).
    """
    if isinstance(exc, MonitorUnavailable):
        return Finding(detection_id, title, unit, STATUS_ABSTAINED, "none", str(exc), "", None,
                       THRESHOLD_VALIDATED, evidence={"abstained": "monitor_unavailable",
                       "http_status": exc.status_code, "retry_after_seconds": exc.retry_after_seconds})
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
        if (ctx.mode == MODE_PRODUCTION and adapter.minimum_age and ctx.resource_created_at is None
                and adapter.detection_id != "DX-004"):  # DX-004 reads usage before gating retirement.
            # A sufficiently old same-instance modification proves a lower bound, not a birth date.
            anchor = (ctx.partition_anchor if adapter.detection_id == "DX-015"
                      else ctx.now)
            if ctx.resource_existed_by is None or anchor - ctx.resource_existed_by < adapter.minimum_age:
                return Finding(adapter.detection_id, adapter.title, _unit(ctx), STATUS_ABSTAINED,
                               "none", f"Insufficient data: {ctx.offer.level} minimum age unverified",
                               "", None, threshold_status_for(adapter.detection_id),
                               evidence={"abstained": "resource_age_unknown",
                                         "age_read_error": ctx.age_read_error})
        return adapter.run(ctx)
    except IncompletePool as exc:
        return Finding(adapter.detection_id, adapter.title, _unit(ctx), STATUS_ABSTAINED,
                       "none", f"Insufficient data: {exc}", "", None,
                       threshold_status_for(adapter.detection_id),
                       evidence={"abstained": exc.reason, "detail": str(exc)})
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
    except IncompleteBatch as exc:
        return Finding(adapter.detection_id, adapter.title, _inventory_unit(ctx), STATUS_ABSTAINED,
                       "none", f"Indexing metrics incomplete: {exc}", "", None,
                       threshold_status_for(adapter.detection_id),
                       evidence={"abstained": "incomplete_indexing_metrics", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return _error_finding(adapter.detection_id, adapter.title, _inventory_unit(ctx), exc)


# --- DX-002: cross-partition query fan-out (Log Analytics; container + serverless) ----

def _fanout_window(ctx, *, one_day: bool = False) -> tuple[TimeWindow | None, list[str]]:
    """Clip to known lifetime and use the same verified resource/log history for both adapters."""
    requested = ctx.window_for(cpq.production_window(ctx.now))
    end = min(ctx.now, requested.end)
    start = max(requested.start, ctx.resource_created_at) if ctx.resource_created_at else requested.start
    if one_day:
        start = max(start, end - timedelta(days=1))
    if start >= end:
        return None, ["no elapsed query observation window"]
    issues = []
    if end - start < timedelta(days=1):
        issues.append("less than 24 hours observed")
    existed_by = ctx.resource_created_at or ctx.resource_existed_by
    if existed_by is None or existed_by > start:
        issues.append("container history unverified at window start")
    logs = ctx.fanout_log_history
    if logs is None or logs.since is None or logs.since > start:
        issues.append((logs.issue if logs else None) or "24-hour logging history unverified")
    return TimeWindow(start, end, requested.granularity), issues


def _dx002_finding(
    ctx: DetectionContext | ServerlessDetectionContext, unit: UnitRef,
) -> Finding:
    """Shared DX-002 verdict→Finding mapping, used by both the container and serverless passes.

    ``la is None`` (no Log Analytics provider) abstains with the ``la_unavailable`` flag so the report's
    consolidated "enable Log Analytics" guardrail picks it up.
    """
    if ctx.la is None:
        return Finding(
            detection_id="DX-002", title="Cross-partition query fan-out", unit=unit,
            status=STATUS_ABSTAINED, severity="none",
            summary="Insufficient data: Log Analytics not configured",
            recommended_action="", agent_kit_rule=None, threshold_status=THRESHOLD_VALIDATED,
            evidence={"abstained": "no Log Analytics provider", "la_unavailable": True},
        )
    window, issues = _fanout_window(ctx)
    if window is None:
        return Finding("DX-002", "Cross-partition query fan-out", unit, STATUS_ABSTAINED, "none",
                       "No elapsed query observation window for this container.", "", None, THRESHOLD_VALIDATED,
                       evidence={"abstained": "no_elapsed_window"})
    start, end = window.start, window.end
    existed_by = ctx.resource_created_at or ctx.resource_existed_by
    logs = ctx.fanout_log_history
    logging_known = logs is not None and logs.since is not None and logs.since <= start
    v = cpq.detect_cross_partition_queries(ctx.la, ctx.account_resource_id, unit.database, unit.container, window)
    evidence = {**v.methodology, "observation_start": start.isoformat(), "observation_end": end.isoformat(),
                "container_existed_by": existed_by.isoformat() if existed_by else None,
                "log_configuration_since": logs.since.isoformat() if logs and logs.since else None,
                "history_issues": issues}
    if v.total_queries > 0:
        evidence.update(total_queries=v.total_queries, observed_partitions=v.container_partitions,
                        fanout_executions=v.measurements.executions)
    if v.root_cause == "log_analytics_unavailable":
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {v.methodology['abstained']}"
    elif issues:
        # Dividing by an unverified day would silently treat unknown time as quiet.
        if not logging_known or existed_by is None or existed_by > start:
            evidence.pop("fanout_queries_per_sec", None)
        observed = (f"{evidence['fanout_executions']:,} of {v.total_queries:,} observed queries fanned out "
                    f"(widest query touched {v.container_partitions} partitions)"
                    if "fanout_executions" in evidence else "No usable query observations")
        status = STATUS_ABSTAINED
        summary = f"Query fan-out: {observed}; not graded ({'; '.join(issues)})."
        evidence["abstained"] = "insufficient_fanout_history"
    elif v.root_cause == "insufficient_data":
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
        severity=v.severity if status == STATUS_FINDING else "none", summary=summary,
        recommended_action=v.recommended_action if status == STATUS_FINDING else "",
        agent_kit_rule="query-avoid-cross-partition" if status == STATUS_FINDING else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=evidence,
    )


def _run_dx002(ctx: DetectionContext) -> Finding:
    return _dx002_finding(ctx, _unit(ctx))


# --- DX-007: shard-key misalignment (structural escalation of DX-002; container + serverless) ----

def _shardkey_finding(ctx: DetectionContext | ServerlessDetectionContext, unit: UnitRef) -> Finding:
    """Expose observations separately from graded re-key advice for both container surfaces."""
    if ctx.la is None:
        return Finding(
            detection_id="DX-007", title="Shard-key misalignment", unit=unit,
            status=STATUS_ABSTAINED, severity="none",
            summary="Insufficient data: Log Analytics not configured",
            recommended_action="", agent_kit_rule=None, threshold_status=THRESHOLD_PROPOSAL,
            evidence={"abstained": "no Log Analytics provider", "la_unavailable": True},
        )
    window, issues = _fanout_window(ctx, one_day=True)
    if window is None:
        return Finding("DX-007", "Shard-key misalignment", unit, STATUS_ABSTAINED, "none",
                       "No elapsed query observation window.", "", None, THRESHOLD_PROPOSAL,
                       evidence={"abstained": "no_elapsed_window"})
    v = skm.detect_shard_key_misalignment(ctx.la, ctx.account_resource_id, unit.database, unit.container,
                                         window, history_issues=issues)
    high = v.kind == "rekey"
    return Finding(
        detection_id="DX-007", title="Shard-key misalignment", unit=unit,
        status=STATUS_FINDING if high else STATUS_ABSTAINED if v.kind == "incomplete" else STATUS_NOT_DETECTED,
        severity="high" if high else "none", summary=v.summary, recommended_action=v.action,
        agent_kit_rule="partition-rekey-migration" if high else None, threshold_status=THRESHOLD_PROPOSAL,
        evidence={**v.evidence, "fanout_result": v.kind},
    )


def _run_dx007(ctx: DetectionContext) -> Finding:
    return _shardkey_finding(ctx, _unit(ctx))


# --- DX-010: uncontrolled ingestion / burst writes (container-scoped, Log Analytics) --

def _run_dx010(ctx: DetectionContext) -> Finding:
    """Report server-side operation counts, not a causal writer or application failure."""
    unit = _unit(ctx)
    o = ctx.offer
    if ctx.la is None:
        return Finding(
            detection_id="DX-010", title="Write activity and server-side throttling", unit=unit,
            status=STATUS_ABSTAINED, severity="none",
            summary="Insufficient data: Log Analytics not configured",
            recommended_action="", agent_kit_rule=None, threshold_status=THRESHOLD_PROPOSAL,
            evidence={"abstained": "no Log Analytics provider", "la_unavailable": True},
        )
    if ctx.dataplane_source is None:
        raise ValueError("No request-log source was selected for DX-010.")
    v = ui.detect_uncontrolled_ingestion(
        ctx.la, ctx.account_resource_id, o.database, o.container,
        ctx.window_for(ui.production_window(ctx.now)), source=ctx.dataplane_source, as_of=ctx.now,
    )
    if v.root_cause in ("log_analytics_unavailable", "insufficient_data", "query_error"):
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.summary}"
    else:
        status = STATUS_FINDING if v.is_uncontrolled else STATUS_NOT_DETECTED
        summary = v.summary
    action = v.recommended_action
    burst = v.methodology.get("burst_factor")
    if action and burst is not None:
        action += (f" Across the observation window, peak write RU was {burst:.1f}× the average "
                   f"of observed {v.methodology['burst_interval']} write buckets (context only).")
    return Finding(
        detection_id="DX-010", title=("Throttling during write activity" if v.is_uncontrolled
                                      else "Write activity and server-side request observations"), unit=unit, status=status,
        severity=v.severity, summary=summary, recommended_action=action,
        agent_kit_rule="sdk-ingestion-rate-control" if v.is_uncontrolled else None,
        threshold_status=THRESHOLD_PROPOSAL, evidence=v.methodology,
    )


# --- DX-001: manual over-provisioning -------------------------------------------------

def _run_dx001(ctx: DetectionContext) -> Finding:
    """Expose measured utilization without prematurely leaking a sizing target or money."""
    o = ctx.offer
    v = op.detect_over_provisioning(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        ctx.window_for(op.production_window(ctx.now)),
        scope_provisioned_ru=ctx.scope_provisioned_ru, resource_created_at=ctx.resource_created_at,
        resource_existed_by=ctx.resource_existed_by, owner_rid=o.owner_rid,
    )
    recoverable = v.wasted_ru if v.is_over_provisioned else None
    sav = _savings_fields(ctx, recoverable)
    if v.band == "insufficient_data":
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {v.methodology.get('abstained', '')}"
    elif v.methodology.get("advice_stage") in {"review", "observation"}:
        status = STATUS_NOT_DETECTED
        summary = (f"Observed manual utilization: p99 {v.trigger_pct:.1f}%, peak "
                   f"{v.methodology['peak_pct']:.1f}% of {o.provisioned_ru:g} RU/s "
                   f"over {v.methodology['evaluated_samples']} samples; "
                   f"{v.methodology['latest_consecutive_hours']} consecutive completed hours.")
        if v.methodology["unverified_leading_zero_samples"]:
            summary += " Leading zero readings without resource-existence evidence do not establish history."
    elif v.is_over_provisioned:
        status = STATUS_FINDING
        summary = (f"{v.band} utilization (p99 {v.trigger_pct:.1f}%, peak {v.methodology['peak_pct']:.1f}% "
                   f"of {o.provisioned_ru:.0f} RU/s across {v.methodology['evaluated_samples']} completed hours); "
                   f"~{v.wasted_ru:.0f} RU/s recoverable by right-sizing")
    else:
        status, summary = STATUS_NOT_DETECTED, (f"Measured p99 utilization {v.trigger_pct:.1f}%, "
                                                f"peak {v.methodology['peak_pct']:.1f}%; no downsize indicated.")
    action = (f"Right-size {o.provisioned_ru:.0f} -> {v.recommended_ru:.0f} RU/s"
              if v.is_over_provisioned else "")
    if v.methodology.get("advice_stage") == "review":
        action = "Review whether this low-utilization week is typical of the workload."
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
                  "visible_observation": status == STATUS_NOT_DETECTED, **sav.get("evidence", {})},
    )


# --- DX-004: idle container -----------------------------------------------------------

def _run_dx004(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    v = idle.detect_idle(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o,
        ctx.window_for(idle.production_window(ctx.now)),
        scope_provisioned_ru=ctx.scope_provisioned_ru, resource_created_at=ctx.resource_created_at,
        resource_existed_by=ctx.resource_existed_by, pool_members=ctx.pool_members,
    )
    recoverable = v.recoverable_ru if v.is_idle else None
    sav = _savings_fields(ctx, recoverable)
    if v.root_cause == "insufficient_data":
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {v.methodology.get('detail') or v.methodology.get('abstained', '')}"
    elif v.is_idle:
        status = STATUS_FINDING
        summary = ("Idle (zero RU for 30 consecutive days); "
                   f"~{v.recoverable_ru:.0f} RU/s recoverable by decommission")
    else:
        status, summary = STATUS_NOT_DETECTED, f"Consumption observed (peak {v.peak_ru:g} RU in a bucket)"
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
        evidence={**v.methodology, **({"age_read_error": ctx.age_read_error} if ctx.age_read_error else {}),
                  **sav.get("evidence", {})},
    )


# --- DX-005: under-provisioning / throttling ------------------------------------------

def _partition_abstention(methodology: dict) -> str:
    """Explain the coverage gap without hiding usable regional or offer-level observations."""
    if "partition_coverage" not in methodology:
        return f"Insufficient data: {methodology.get('abstained', '')}"
    regions = "; ".join(
        f"{r['region']}: {r['usable']} usable, expected "
        f"{r['expected'] if r['expected'] is not None else 'unknown'}"
        for r in methodology["partition_coverage"])
    summary = "Incomplete partition coverage: " + (regions or "no configured regions available")
    read_limits = sorted({issue.split(":", 1)[1] for row in methodology["partition_coverage"]
                          for issue in row["issues"] if "_read_error:Azure Monitor " in issue})
    return "; ".join([summary, *read_limits])


def _run_dx005(ctx: DetectionContext) -> Finding:
    """Keep offer-level observed counts separate from the two-hour capacity diagnosis."""
    o = ctx.offer
    v = up.detect_under_provisioning(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o,
        ctx.window_for(up.production_window(ctx.now)), resource_created_at=ctx.resource_created_at,
        regions=ctx.partition_regions,
        pool_members=ctx.pool_members, read_counts=ctx.read_counts,
        as_of=ctx.now,
    )
    throttled = v.methodology.get("throttled_requests", 0)
    total = v.methodology.get("total_requests")
    observed = (_observed_429s(throttled, total) if total is not None else
                f"{throttled:,} HTTP 429s observed; offer rate unknown")
    if v.root_cause == "insufficient_data":
        status, summary, rule = STATUS_ABSTAINED, _partition_abstention(v.methodology), None
        if throttled and v.methodology.get("abstained") == "too_few_requests":
            summary = f"{observed}; not enough requests to judge capacity"
        elif throttled:
            summary += f"; {observed}. A capacity diagnosis is inconclusive"
    elif v.is_under_provisioned:
        status = STATUS_FINDING
        hours = v.methodology["intervals"]
        details = "; ".join(f"{h['start']}: {_observed_429s(h['throttled_requests'], h['total_requests'])}"
                            for h in hours)
        summary = f"Broad saturation across all configured regions in two consecutive completed hours: {details}"
        rule = "throughput-autoscale" if o.mode == "autoscale" else "throughput-right-size"
    elif v.root_cause == "skew_suspected":
        # Skew is DX-006's domain — DX-005 reports no *global* under-provisioning here.
        status = STATUS_NOT_DETECTED
        summary = (f"{observed}; a hot physical partition and a cooler one were observed in "
                   f"{v.methodology['witness_region']}. See the DX-006 hot-partition check")
        if not v.methodology["coverage_complete"]:
            summary += "; partial partition coverage"
        rule = None
    elif v.root_cause == "regional_saturation":
        status, summary, rule = (STATUS_NOT_DETECTED,
                                 f"{observed}; saturation was observed in some regions, not across the offer", None)
    elif v.root_cause == "throttling_without_saturation":
        status, summary, rule = (STATUS_NOT_DETECTED,
                                 f"{observed}. The partition measurements showed neither broad saturation "
                                 "nor a hot partition. They do not explain the throttling or justify more RU/s", None)
    elif v.root_cause == "below_throttle_threshold":
        status, summary, rule = (STATUS_NOT_DETECTED,
                                 f"{observed}; below the {v.methodology['thresholds']['throttle_rate_pct']:g}% "
                                 "throttling threshold", None)
    elif v.root_cause == "pressure_observed":
        status, summary, rule = (STATUS_NOT_DETECTED, f"{observed}; two consecutive completed hours of "
                                 "verified broad pressure were not established", None)
    else:
        status, summary, rule = STATUS_NOT_DETECTED, "No HTTP 429s observed", None
    return Finding(
        detection_id="DX-005", title="Under-provisioning / throttling", unit=_unit(ctx),
        status=status, severity=v.severity, summary=summary,
        recommended_action=v.recommended_action, agent_kit_rule=rule,
        threshold_status=THRESHOLD_VALIDATED, evidence={**v.methodology, "root_cause": v.root_cause,
                                                       "observed_throttling": bool(throttled)},
    )


# --- DX-006: hot partition ------------------------------------------------------------

def _run_dx006(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    # New resources need an observable first interval, even before the next closed hour.
    anchor = ctx.partition_anchor
    if ctx.resource_created_at and ctx.resource_created_at > anchor - timedelta(days=1):
        anchor = ctx.now
    v = hp.detect_hot_partition(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o,
        ctx.window_for(hp.production_window(anchor)), resource_created_at=ctx.resource_created_at, as_of=ctx.now,
        regions=ctx.partition_regions,
        pool_members=ctx.pool_members, read_counts=ctx.read_counts,
    )
    if v.root_cause == "insufficient_data":
        status = STATUS_ABSTAINED
        summary = _partition_abstention(v.methodology)
    elif v.is_hot_partition or v.root_cause == "skew_observed":
        status = STATUS_FINDING if v.is_hot_partition else STATUS_ABSTAINED
        hours = v.methodology["intervals"]
        details = []
        for h in hours:
            t, r = h["total_requests"], h["throttled_requests"]
            impact = (_observed_429s(r, t) if t is not None and r is not None else
                      f"{r:,} measured 429s, offer rate unknown" if r is not None else
                      f"{t:,} requests, offer throttling unknown" if t is not None else "offer throttling unknown")
            details.append(f"{h['start']} to {h['end']}: {h['hot_id']} reached {h['hot_pct']:g}%, "
                           f"{h['cool_id']} peaked at {h['cool_pct']:g}% ({impact})")
        summary = f"Observed partition skew in {v.methodology['witness_region']}: " + "; ".join(details)
        if not v.is_hot_partition:
            summary += "; observation only, no second consecutive completed hour for this hot partition"
        if not v.methodology["coverage_complete"]:
            summary += "; partial partition coverage"
    else:
        status, summary = STATUS_NOT_DETECTED, "No within-region hot partition detected"
    other_throttles = v.methodology.get("other_observed_429s", v.methodology.get("window_observed_429s"))
    if other_throttles:
        scope = "outside the reported intervals" if "intervals" in v.methodology else "in the window"
        summary += f"; {other_throttles:,} offer-level HTTP 429s observed {scope}, not attributed to skew"
    return Finding(
        detection_id="DX-006", title="Hot partition", unit=_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="partition-high-cardinality" if v.is_hot_partition else None,
        threshold_status=THRESHOLD_VALIDATED, evidence={**v.methodology, "root_cause": v.root_cause,
                                                        "observed_throttling": bool(v.methodology.get("window_observed_429s"))},
    )


# --- DX-015: partition storage skew ---------------------------------------------------

def _run_dx015(ctx: DetectionContext) -> Finding:
    """Combine independent storage observations; only a recent logical-key sample can be High."""
    o = ctx.offer
    logical = ctx.logical_storage or LogicalStorage("configuration_unknown",
        "Logical-key risk not assessed: diagnostic settings unverified. Check PartitionKeyStatistics configuration.")
    try:
        v = ss.detect_storage_skew(
            ctx.metrics, ctx.account_resource_id, o.database, o.container, o,
            ctx.window_for(ss.production_window(ctx.partition_anchor)), resource_created_at=ctx.resource_created_at,
            regions=ctx.partition_regions,
        )
    except Exception as exc:  # noqa: BLE001 - preserve the independent logical result
        physical = _error_finding("DX-015", "Partition storage skew", _unit(ctx), exc)
        evidence = physical.evidence.copy()
        status, summary = physical.status, physical.summary
    else:
        evidence = {**v.methodology, "physical_result": v.root_cause}
        status = STATUS_NOT_DETECTED
        if v.root_cause == "insufficient_data":
            status, summary = STATUS_ABSTAINED, _partition_abstention(v.methodology)
        elif v.is_storage_skew:
            summary = (f"Physical storage skew in {v.methodology['witness_region']} at {v.methodology['witness_hour']}: "
                       f"{v.max_bytes/1024**3:.1f} GiB vs {v.min_bytes/1024**3:.1f} GiB. "
                       "Check the largest logical partitions.")
            if not v.methodology["coverage_complete"]:
                summary += " Physical partition coverage is partial."
        else:
            summary = "No material within-region physical storage skew observed."
    high = logical.status == "high"
    evidence["logical_partition_storage"] = asdict(logical)
    return Finding(
        detection_id="DX-015", title="Logical partition storage risk" if high else "Partition storage skew",
        unit=_unit(ctx), status=STATUS_FINDING if high else status, severity="high" if high else "none",
        summary=f"{summary} {logical.message}",
        recommended_action="Review the largest logical keys and their growth before changing the partition key." if high else "",
        agent_kit_rule="partition-high-cardinality" if high else None,
        threshold_status=THRESHOLD_PROPOSAL, evidence=evidence,
    )


# --- DX-011: autoscale maximum right-sizing -----------------------------------------

def _run_dx011(ctx: DetectionContext) -> Finding:
    """Keep the utilization finding while distinguishing analytical reductions from no-op targets."""
    o = ctx.offer
    v = asig.detect_autoscale_max_over_provisioned(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        ctx.window_for(op.production_window(ctx.now)),
        scope_provisioned_ru=ctx.scope_provisioned_ru, resource_created_at=ctx.resource_created_at,
        pool_members=ctx.pool_members,
    )
    recoverable = v.wasted_ru if v.is_over_provisioned else None
    sav = _savings_fields(ctx, recoverable)
    if v.band == "insufficient_data":
        reason = v.methodology.get("detail") or v.methodology.get("abstained", "")
        status, summary = STATUS_ABSTAINED, f"Insufficient data: {reason}"
    elif v.methodology.get("advice_stage") in {"review", "observation"}:
        status = STATUS_NOT_DETECTED
        summary = (f"Measured autoscale peak {v.methodology['peak_scaled_ru']:g} RU/s "
                   f"({v.trigger_pct:.1f}% of {o.provisioned_ru:g} RU/s maximum) "
                   f"over {v.methodology['evaluated_samples']} samples; "
                   f"{v.methodology['latest_consecutive_hours']} consecutive completed hours.")
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
        summary = f"Measured autoscale peak {v.trigger_pct:.1f}% of maximum; no downsize indicated."
    action = ""
    if v.methodology.get("advice_stage") == "review":
        action = "Review whether this week's low scaled throughput is typical of the workload."
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
                  "visible_observation": status == STATUS_NOT_DETECTED, **sav.get("evidence", {})},
    )


def _run_dx013(ctx: DetectionContext) -> Finding:
    """Compare actual scaled throughput with fixed manual throughput at the same capacity."""
    o = ctx.offer
    v = ms.detect_autoscale_to_manual(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        ctx.window_for(op.production_window(ctx.now)), resource_created_at=ctx.resource_created_at, account=ctx.account_config,
    )
    return _mode_finding(ctx, v, "DX-013", "Autoscale to manual candidate", "throughput-right-size")


# --- DX-012: manual -> autoscale at equal capacity -----------------------------------

def _run_dx012(ctx: DetectionContext) -> Finding:
    """Compare each measured hourly peak, not a duty-cycle heuristic."""
    o = ctx.offer
    v = ms.detect_manual_to_autoscale(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        ctx.window_for(op.production_window(ctx.now)), resource_created_at=ctx.resource_created_at, account=ctx.account_config,
        resource_existed_by=ctx.resource_existed_by,
    )
    return _mode_finding(ctx, v, "DX-012", "Manual to autoscale candidate", "throughput-autoscale")


def _mode_finding(ctx, v, detector, title, rule):
    """Surface reviews without an actionable finding, recoverable quantity, or estimated dollars."""
    status = (STATUS_ABSTAINED if v.root_cause == "no_data" else
              STATUS_FINDING if v.recommend_switch else STATUS_NOT_DETECTED)
    return Finding(
        detection_id=detector, title=title, unit=_unit(ctx), status=status,
        severity=v.severity, summary=v.summary, recommended_action=v.recommended_action,
        agent_kit_rule=rule if v.recommend_switch else None,
        threshold_status=THRESHOLD_PROPOSAL, evidence={**v.methodology, "root_cause": v.root_cause,
                                                      "visible_observation": status == STATUS_NOT_DETECTED},
    )


# --- DX-009: partition merge candidate (over-partitioned) -----------------------------

def _run_dx009(ctx: DetectionContext) -> Finding:
    o = ctx.offer
    # PhysicalPartitionCount supports only a 5-minute grain, so DX-009 uses its own recent window
    # (partition count is slow-moving state) regardless of the run mode.
    v = pm.detect_partition_merge(
        ctx.metrics, ctx.account_resource_id, o.database, o.container, o.provisioned_ru,
        pm.recent_window(ctx.now), storage_peak=ctx.storage_peak,
        account_config=ctx.account_config,
    )
    if v.root_cause == "insufficient_data":
        status, summary = STATUS_ABSTAINED, "Insufficient data: no partition-count telemetry"
    elif v.root_cause == "storage_unknown":
        status = STATUS_ABSTAINED
        summary = (f"Observed {v.actual_partitions} physical partitions; storage is unknown. "
                   "Cannot determine how many partitions are needed.")
        if v.methodology["merge_eligibility"] == "blocked_pitr":
            summary += " Partition merge is currently blocked by continuous backup (PITR)."
    elif v.is_over_partitioned:
        status = STATUS_FINDING
        summary = (f"Over-partitioned: {v.actual_partitions} physical partitions but only "
                   f"{v.needed_partitions} needed (~{v.ru_per_partition:.0f} RU/s each)")
        eligibility = v.methodology["merge_eligibility"]
        if eligibility == "blocked_pitr":
            summary += "; partition merge currently blocked by continuous backup (PITR)"
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
        threshold_status=THRESHOLD_VALIDATED, evidence={**v.methodology, "actual_partitions": v.actual_partitions or None,
                                                       "storage_bytes": v.storage_bytes},
    )


# --- DX-017: rapid storage growth -----------------------------------------------------

def _run_dx017(ctx: DetectionContext) -> Finding:
    """Report observed container data changes; do not generate a capacity deadline or graded issue."""
    o = ctx.offer
    evidence = sg.detect_storage_growth(
        ctx.metrics, ctx.account_resource_id, o.database, o.container,
        ctx.window_for(sg.production_window(ctx.now)),
    )
    action = ""
    if not evidence["measured_hours"]:
        status, summary = STATUS_ABSTAINED, "No container data-storage measurements available"
    else:
        status = STATUS_NOT_DETECTED
        evidence["visible_observation"] = True
        summary = (f"Container data storage: {evidence['first_bytes'] / sg.GIB:,.3g} GiB "
                   f"at {evidence['first_sample_utc']}")
        if evidence["change_bytes"] is not None:
            summary += (f" to {evidence['last_bytes'] / sg.GIB:,.3g} GiB at {evidence['last_sample_utc']} "
                        f"({evidence['change_bytes'] / sg.GIB:+,.3g} GiB measured change, not a forecast)")
        else:
            summary += "; one measurement cannot establish a change"
        if days := evidence["retention_review_days"]:
            action = (f"Storage ended higher than it began on each fully measured UTC day from "
                      f"{days[0]} through {days[-1]}. Review retention or archival needs with the data owner.")
    return Finding(
        detection_id="DX-017", title="Rapid storage growth", unit=_unit(ctx), status=status,
        severity="none", summary=summary, recommended_action=action,
        agent_kit_rule=None, threshold_status=threshold_status_for("DX-017"), evidence=evidence,
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
    DetectionAdapter("DX-004", "Idle container", _is_metrics_scoped, _run_dx004, minimum_age=idle.AGE_FLOOR),
    DetectionAdapter("DX-005", "Under-provisioning / throttling", _is_metrics_scoped, _run_dx005),
    DetectionAdapter("DX-006", "Hot partition", _is_metrics_scoped, _run_dx006),
    DetectionAdapter("DX-015", "Partition storage skew", _is_container, _run_dx015,
                     optional_requires=frozenset({CAP_LA_KEYSTATS})),
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
    v = mrw.detect_multi_region_writes(ctx.config, ctx.throughput_offers, inventory_issues=ctx.inventory_issues)
    review = v.root_cause == "nonprod_multi_region_writes"
    if review or v.is_antipattern:
        status = STATUS_NOT_DETECTED if review else STATUS_FINDING
        summary = _dx008_summary(v)
    elif v.root_cause == "legitimate_ha":
        status = STATUS_NOT_DETECTED
        summary = "Multi-region writes on a production account — treated as intentional RTO=0 HA"
    else:
        status, summary = STATUS_NOT_DETECTED, "Multi-region writes are not enabled"
    client_review = v.methodology.get("client_write_failover") == "not_assessed"
    title = "Review writable regions" if review else "Multi-region writes antipattern"
    return Finding(
        detection_id="DX-008", title="Verify client write failover" if client_review else title, unit=_account_unit(ctx),
        status=status, severity=v.severity, summary=summary,
        recommended_action=v.recommended_action,
        agent_kit_rule="global-multi-region-write-antipattern" if v.is_antipattern and not client_review else None,
        threshold_status=THRESHOLD_VALIDATED,
        evidence={**v.methodology, "root_cause": v.root_cause},
    )


def _dx008_summary(v: mrw.MultiRegionWriteVerdict) -> str:
    """Report the observed topology and verified footprint without inferring removable capacity."""
    capacity = v.methodology["regional_capacity"]
    if v.methodology.get("client_write_failover") == "not_assessed":
        summary = (f"Multi-region writes enabled for {v.methodology['api_family']}; "
                   "application write failover has not been verified")
    elif v.root_cause == "nonprod_multi_region_writes":
        summary = (
            f"Multi-region writes across {v.write_region_count} write regions on a "
            "non-production account. Review whether these regions support availability or failover testing"
        )
    else:
        summary = "Multi-region writes are enabled with only one write region; adding another region can change billing"
    if (
        capacity["status"] == "quantified"
        and _is_positive_finite(capacity.get("configured_per_region_ru"))
        and _is_positive_finite(capacity.get("global_regional_ru"))
    ):
        summary += (
            f"; {capacity['configured_per_region_ru']:,.0f} RU/s per region yields "
            f"{capacity['global_regional_ru']:,.0f} regional RU/s globally"
        )
    elif v.root_cause == "nonprod_multi_region_writes":
        summary += "; regional throughput footprint not quantified"
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
        if v.root_cause == "unknown":
            status, summary = STATUS_ABSTAINED, "Consistency level or region count is unknown"
        else:
            status, summary = STATUS_NOT_DETECTED, f"No quorum-read review for {v.consistency_level}"
    return Finding(
        detection_id="DX-016", title="Expensive consistency", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="global-consistency" if v.is_expensive else None,
        threshold_status=THRESHOLD_VALIDATED, evidence=evidence,
    )


# --- DX-019: PITR (continuous backup) on a non-production account (account-scoped) -----


def _dx019_storage_cost(ctx: AccountDetectionContext) -> dict:
    """Price current backup retention, not recoverable savings or a customer bill."""
    if ctx.arm is None:
        raise ValueError("ARM provider unavailable")
    if ctx.retail_prices is None:
        raise ValueError("Retail Prices provider unavailable")
    if not ctx.config.location_names or len(ctx.config.location_names) != ctx.config.region_count:
        raise ValueError("account region inventory is incomplete")

    expected = tuple(ctx.arm.list_containers(ctx.resource_group, ctx.account))
    canonical_regions = ctx.arm.resolve_arm_region_names(ctx.config.location_names)
    if (len(canonical_regions) != ctx.config.region_count or
            len(set(canonical_regions)) != len(canonical_regions)):
        raise ValueError("account region mapping is incomplete")
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
        expected_containers=expected,
    )
    snapshot = select_complete_storage_snapshot(
        samples,
        expected,
        reference_region,
        ctx.now,
    )
    prices = ctx.retail_prices.pitr_storage_prices(canonical_regions, as_of=ctx.now)
    if sorted(p.arm_region_name for p in prices) != sorted(canonical_regions):
        raise ValueError("Retail Prices did not return exactly one price per configured region")
    currencies = {price.currency for price in prices}
    if len(currencies) != 1:
        raise ValueError("Retail Prices returned mixed currencies")
    currency = next(iter(currencies))
    regional_rate = sum(price.rate_per_gb_month for price in prices)
    amount = round(snapshot.decimal_gb * regional_rate, 2)
    return {
        "estimated_monthly_backup_storage_cost": amount,
        "cost_currency": currency,
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
        "formula": "logical_storage_gb_decimal * sum(per_region_current_storage_rate_per_gb_month)",
        "restore_charges_included": False,
    }


def _run_dx019(ctx: AccountDetectionContext) -> Finding:
    """Keep the protective retention choice visible even when its current cost cannot be estimated."""
    v = pitr.detect_pitr_on_nonprod(ctx.config)
    evidence = dict(v.methodology)
    evidence["root_cause"] = v.root_cause
    if v.is_antipattern:
        status = STATUS_NOT_DETECTED
        evidence["visible_observation"] = True
        summary = (f"Continuous backup / PITR ({v.continuous_backup_tier or 'continuous'}) on a "
                   f"non-production account — review the required recovery window")
        try:
            evidence.update(_dx019_storage_cost(ctx))
            summary += (f"; estimated monthly backup-storage cost at retail rates: "
                        f"{evidence['cost_currency']} {evidence['estimated_monthly_backup_storage_cost']:,.2f}")
        except Exception as exc:  # noqa: BLE001 - enrichment must never suppress the qualitative finding
            summary += "; monthly backup-storage cost unavailable"
            evidence["cost_enrichment"] = {
                "status": "unavailable",
                "reason": f"{type(exc).__name__}: {str(exc)[:200]}",
            }
    elif v.root_cause == "legitimate_prod_backup":
        status, summary = STATUS_NOT_DETECTED, "No positive non-production classification; no retention review"
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
    )


# --- DX-020: non-throttling error-code analysis (account-scoped, metrics only) ---------

def _run_dx020(ctx: AccountDetectionContext) -> Finding:
    """Keep 4xx context visible without using it to grade or explain a 5xx service response."""
    window = ctx.window_for(ea.production_window(ctx.now))
    evidence = ea.observe(ctx.metrics, ctx.account_resource_id, window)
    severity, action = "none", ""
    if rows := evidence["affected_intervals"]:
        rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
        row = max(rows, key=lambda r: (rank[r["severity"]], r["service_error_rate_pct"], r["start_utc"]))
        severity = row["severity"]
        status = STATUS_FINDING if severity != "none" else STATUS_NOT_DETECTED
        evidence["visible_observation"] = status == STATUS_NOT_DETECTED
        counts = ", ".join(f"HTTP {c}: {n:,} ({row['status_rates_pct'][c]:.3g}%)"
                           for c, n in row["status_code_counts"].items())
        summary = (f"[{row['start_utc']}, {row['end_utc']}): {row['total_requests']:,} server responses; "
                   f"{counts}. 5xx alone: {row['service_error_rate_pct']:.3g}%; {len(rows)} affected interval(s)")
        action = ("Check SDK diagnostics and service health for the observed 5xx interval. "
                  if severity != "none" else "")
        action += ("Status counts alone do not identify a cause or failed user requests. "
                   "Check application intent before interpreting 4xx, including expected misses, "
                   "conflicts or precondition failures.")
    elif evidence["measured_intervals"]:
        status, summary = STATUS_NOT_DETECTED, "No non-429 4xx or 5xx responses observed"
    else:
        status, summary = STATUS_ABSTAINED, "No status-code measurements available"
    return Finding(
        detection_id="DX-020", title="Error-code analysis", unit=_account_unit(ctx), status=status,
        severity=severity, summary=summary, recommended_action=action, agent_kit_rule=None,
        threshold_status=threshold_status_for("DX-020"), evidence=evidence,
    )


# --- DX-021: throttling root-cause decomposition (account-scoped, metrics only) --------

def _observed_429s(throttled: float, total: float) -> str:
    """Keep exact counts visible even when rounding a small positive rate would display zero."""
    counts = f"{throttled:,.0f} of {total:,.0f} requests returned HTTP 429"
    if not total:
        return counts
    rate = 100 * throttled / total
    label = f"{rate:.3g}"
    if rate < 1 and label == "1":
        label = "<1"
    return f"{counts} ({label}%)"


def _run_dx021(ctx: AccountDetectionContext) -> Finding:
    """Describe which operations received throttles, never inferred causes or a second issue."""
    window = ctx.window_for(trc.production_window(ctx.now))
    evidence = trc.observe(ctx.metrics, ctx.account_resource_id, window)
    if rows := evidence["affected_intervals"]:
        status = STATUS_NOT_DETECTED
        evidence["observed_throttling"] = True
        row = max(rows, key=lambda r: (r["total_throttled"], r["start_utc"]))
        summary = (f"{_observed_429s(row['total_throttled'], row['total_requests'])} "
                   f"in [{row['start_utc']}, {row['end_utc']}); {len(rows)} affected interval(s). ")
        if row["attribution"] == "reconciled":
            summary += "Recipients (share of all 429s): " + ", ".join(
                f"{op}: {n:,} ({row['op_share_of_429s_pct'][op]:.3g}%)"
                for op, n in row["op_throttled_counts"].items())
        else:
            summary += "Operation attribution unavailable; no reconciled same-hour breakdown"
    elif evidence["measured_intervals"]:
        status, summary = STATUS_NOT_DETECTED, "No HTTP 429s observed"
    else:
        status, summary = STATUS_ABSTAINED, "No account request status measurements available"
    return Finding(
        detection_id="DX-021", title="Throttling by operation", unit=_account_unit(ctx), status=status,
        severity="none", summary=summary, recommended_action="", agent_kit_rule=None,
        threshold_status=threshold_status_for("DX-021"), evidence=evidence,
    )


# --- DX-022: Per-Region Provisioned Autoscale opportunity (account-scoped, ARM) --------

def _run_dx022(ctx: AccountDetectionContext) -> Finding:
    v = prpa.detect_prpa_candidate(ctx.config, ctx.throughput_offers, inventory_complete=not ctx.inventory_issues)
    if v.is_candidate:
        status = STATUS_FINDING
        summary = "Dynamic autoscale is disabled on an account with confirmed autoscale throughput"
    else:
        summary = {
            "no_autoscale_offers": "No autoscale offer in the verified inventory",
            "unknown_offers": "Incomplete inventory: no autoscale offer could be verified",
            "unknown_setting": "Dynamic autoscale setting was not reported by ARM",
            "already_enabled": "Dynamic autoscale already enabled",
            "serverless": "Serverless — no provisioned per-region autoscale",
        }[v.root_cause]
        status = STATUS_ABSTAINED if v.root_cause.startswith("unknown_") else STATUS_NOT_DETECTED
    return Finding(
        detection_id="DX-022", title="Dynamic autoscale", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule=None, threshold_status=threshold_status_for("DX-022"), evidence=v.methodology,
    )


# --- DX-023: Reserved Capacity opportunity (account-scoped) ----------------------------

def _run_dx023(ctx: AccountDetectionContext) -> Finding:
    v = rc.detect_reserved_capacity_candidate(
        ctx.scope_provisioned_ru, is_serverless=ctx.config.is_serverless,
        confirmed_provisioned=bool(ctx.throughput_offers) or ctx.config.capability_inventory_complete,
    )
    if v.root_cause == "reservation_review":
        status = STATUS_NOT_DETECTED
        summary = "Review existing reservation coverage for provisioned throughput in Cost Management"
    elif v.root_cause == "unknown":
        status, summary = STATUS_ABSTAINED, "No provisioned throughput could be confirmed"
    else:
        summary = "Serverless — nothing provisioned to reserve"
        status = STATUS_NOT_DETECTED
    return Finding(
        detection_id="DX-023", title="Reserved capacity", unit=_account_unit(ctx), status=status,
        severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule=None, threshold_status=threshold_status_for("DX-023"), evidence=v.methodology,
    )


# --- DX-014: provisioned -> serverless candidate (account-scoped) ----------------------

def _run_dx014(ctx: AccountDetectionContext) -> Finding:
    """Return one account result, never a migration directive or a rollup savings estimate."""
    v = svc.detect_serverless_candidate(
        ctx.metrics, ctx.account_resource_id, ctx.window_for(svc.production_window(ctx.now)),
        account=ctx.config, offers=ctx.throughput_offers, inventory_issues=ctx.inventory_issues, cost=ctx.cost,
    )
    status = (STATUS_FINDING if v.root_cause == "serverless_candidate" else STATUS_NOT_DETECTED
              if v.root_cause in {"not_applicable", "not_cheaper"} else STATUS_ABSTAINED)
    return Finding(
        detection_id="DX-014", title="Serverless candidate", unit=_account_unit(ctx), status=status,
        severity="low" if status == STATUS_FINDING else "none", summary=v.summary,
        recommended_action=v.recommended_action, agent_kit_rule=None,
        threshold_status=THRESHOLD_VALIDATED, evidence=v.methodology,
    )


ACCOUNT_REGISTRY: list[AccountDetectionAdapter] = [
    AccountDetectionAdapter("DX-008", "Multi-region writes antipattern", _run_dx008),
    AccountDetectionAdapter(
        "DX-016", "Expensive consistency", _run_dx016,
        optional_requires=frozenset({CAP_LA_REQUEST_AGGREGATES}),
    ),
    AccountDetectionAdapter("DX-014", "Serverless candidate", _run_dx014,
                            optional_requires=frozenset({CAP_COST_MANAGEMENT})),
    AccountDetectionAdapter("DX-019", "PITR on non-prod", _run_dx019),
    AccountDetectionAdapter("DX-020", "Error-code analysis", _run_dx020),
    AccountDetectionAdapter("DX-021", "Throttling by operation", _run_dx021),
    AccountDetectionAdapter("DX-022", "Dynamic autoscale", _run_dx022),
    AccountDetectionAdapter("DX-023", "Reserved capacity", _run_dx023),
]


# --- DX-003: shared-throughput starvation (database-scoped, Log Analytics) -------------

def _run_dx003(ctx: DatabaseDetectionContext) -> Finding:
    if ctx.dataplane_source is None:
        raise ValueError("No request-log source was selected for DX-003.")
    win = ctx.window_for(sht.production_window(ctx.now, ctx.dataplane_source))
    v = sht.detect_shared_throughput_starvation(
        ctx.la, ctx.account_resource_id, ctx.database, ctx.shared_ru, win,
        source=ctx.dataplane_source, pool_members=ctx.pool_members, as_of=ctx.now,
    )
    observed = v.methodology.get("observed_429s", 0)
    if v.root_cause in ("log_analytics_unavailable", "insufficient_data", "query_error"):
        status = STATUS_ABSTAINED
        summary = f"Insufficient data: {v.methodology.get('abstained', v.root_cause)}"
        if observed:
            summary += f"; {_observed_429s(observed, v.methodology['observed_requests'])} among observed members"
    elif v.is_starvation or v.root_cause == "possible_contention":
        status = STATUS_FINDING if v.is_starvation else STATUS_NOT_DETECTED
        bins = v.methodology["intervals"]
        label = "Likely shared-pool contention" if v.is_starvation else "Possible shared-pool contention"
        summary = (f"{label} in '{v.database}', {bins[0]['start']} to {bins[-1]['end']}: "
                   f"'{v.monopolizer}' dominated measured RU while '{v.victim}' was throttled "
                   f"in {len(bins)} completed five-minute interval(s). In the last interval "
                   f"'{v.monopolizer}' consumed {v.monopolizer_ru_share_pct:g}% of active members' RU; "
                   f"for '{v.victim}', {_observed_429s(bins[-1]['affected_429s'], bins[-1]['affected_requests'])}.")
    else:
        status = STATUS_NOT_DETECTED
        summary = "No sustained shared-pool contention established in the observed intervals"
        if observed:
            summary += f"; {_observed_429s(observed, v.methodology['observed_requests'])} among observed members"
    return Finding(
        detection_id="DX-003", title="Shared-throughput starvation", unit=_database_unit(ctx),
        status=status, severity=v.severity, summary=summary, recommended_action=v.recommended_action,
        agent_kit_rule="throughput-container-vs-database" if v.is_starvation else None,
        threshold_status=THRESHOLD_VALIDATED, evidence={**v.methodology, "root_cause": v.root_cause,
                                                        "observed_throttling": bool(observed)},
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
    return _dx002_finding(ctx, _serverless_unit(ctx))


def _run_dx007_serverless(ctx: ServerlessDetectionContext) -> Finding:
    """DX-007 on a serverless container (same fan-out signal as the container pass)."""
    return _shardkey_finding(ctx, _serverless_unit(ctx))


# --- DX-018: serverless throttling (serverless-container-scoped) -----------------------

def _run_dx018(ctx: ServerlessDetectionContext) -> Finding:
    """Keep the worst incident visible, but gate account capacity-mode advice on recurrence."""
    evidence = svt.detect_serverless_throttling(
        ctx.metrics, ctx.account_resource_id, ctx.database, ctx.container,
        ctx.window_for(svt.production_window(ctx.now)),
    )
    severity, action = "none", ""
    if rows := evidence["affected_intervals"]:
        rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
        row = max(rows, key=lambda r: (rank[r["severity"]], r["throttle_rate_pct"] or 0, r["start_utc"]))
        severity = row["severity"]
        status = STATUS_FINDING if severity != "none" else STATUS_NOT_DETECTED
        evidence["observed_throttling"] = True
        label = (_observed_429s(row["total_throttled"], row["total_requests"])
                 if row["throttle_rate_pct"] is not None else
                 f"{row['total_throttled']:,} HTTP 429 responses; same-hour rate unavailable")
        summary = f"{label} in [{row['start_utc']}, {row['end_utc']}); {len(rows)} affected interval(s)"
        if severity != "none":
            action = ("Investigate this server-side throttling interval using SDK retry diagnostics and "
                      "request distribution. Container counts do not identify a hot partition or client failures.")
        if evidence["capacity_mode_review"]:
            action += (" Ask the owner whether this traffic is representative. If it is, evaluate "
                       "provisioned throughput for the account; a mode change does not fix a hot key.")
    elif evidence["measured_pairs"]:
        status, summary = STATUS_NOT_DETECTED, "No HTTP 429s in the paired container request measurements"
    else:
        status, summary = STATUS_ABSTAINED, "No paired container request and 429 measurements"
    return Finding(
        detection_id="DX-018", title="Serverless throttling", unit=_serverless_unit(ctx),
        status=status, severity=severity, summary=summary, recommended_action=action,
        agent_kit_rule="throughput-serverless" if evidence["capacity_mode_review"] else None,
        threshold_status=threshold_status_for("DX-018"), evidence=evidence,
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
        status = STATUS_NOT_DETECTED
        summary = (f"Index storage: {v.index_bytes:,.0f} bytes; data storage: {v.data_bytes:,.0f} bytes "
                   f"(index is {v.ratio:.1%} of data). Review index usage.")
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

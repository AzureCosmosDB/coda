"""Shared capacity-materiality severity (framework layer).

Severity model for the cost detections (DX-001 right-size, DX-004 idle decommission). CODA
expresses savings as **capacity (RU/s), not dollars** (ADR-0012) — it has no access to a customer's
billed rates, so a dollar figure would be an unverifiable assertion. Severity is therefore
**relative materiality in capacity terms** (ADR-0006): a finding's RU/s as a percentage of the
scope's total provisioned RU/s. The *amount* is computed by each detection; only the severity
mapping is shared here.

**Capacity is not cost** (do not cost-normalize — ADR-0012): autoscale RU/s ≈ 1.5× manual per RU/s,
and manual cost multiplies by region count (autoscale multi-region depends on per-partition/
per-region autoscale). CODA surfaces that as a documented caveat and lets the customer — who knows
their own rates and topology — convert capacity to cost.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MaterialityConfig:
    """Severity cutoffs. Relative (% of scope provisioned RU/s) when scope is known, else absolute RU/s."""

    material_high_pct: float = 5.0
    material_med_pct: float = 1.0
    abs_high_ru: float = 5000.0
    abs_med_ru: float = 1000.0


def severity(
    finding_ru: float,
    scope_provisioned_ru: float | None,
    config: MaterialityConfig | None = None,
    *,
    applicable: bool = True,
) -> tuple[str, float | None]:
    """Map a finding's RU/s to ``(severity, materiality_pct)`` — capacity-relative (ADR-0012).

    Args:
        finding_ru: The finding's RU/s (wasted for right-size, recoverable for idle).
        scope_provisioned_ru: Total provisioned RU/s of the scope in view (the materiality
            denominator). If ``None``/zero, severity falls back to absolute-RU bands.
        config: Tunable cutoffs.
        applicable: ``False`` when the finding does not apply (not over-provisioned / not idle)
            -> ``("none", None)``. Lets callers keep a single severity call site.

    Returns:
        ``(severity, materiality_pct)`` where ``materiality_pct`` (finding RU/s as % of scope
        provisioned RU/s) is populated only in the relative (scope-known) branch, else ``None``.
    """
    cfg = config or MaterialityConfig()
    if not applicable:
        return "none", None
    if scope_provisioned_ru and scope_provisioned_ru > 0:
        pct = finding_ru / scope_provisioned_ru * 100.0
        if pct >= cfg.material_high_pct:
            return "high", pct
        if pct >= cfg.material_med_pct:
            return "medium", pct
        return "low", pct
    if finding_ru >= cfg.abs_high_ru:
        return "high", None
    if finding_ru >= cfg.abs_med_ru:
        return "medium", None
    return "low", None


@dataclass(frozen=True)
class CostMaterialityConfig:
    """Severity cutoffs for **cost-relative** FinOps findings (finding spend / scope spend).

    Mirrors :class:`MaterialityConfig` but in billed-currency terms. Used only by FinOps detections,
    which gate on the ``cost_management`` capability — so a real dollar figure is grounded in the
    customer's actual Cost Management data, not an assertion (ADR-0012). Absolute bands are a fallback
    when the scope's total spend is unknown; amounts are in the subscription's billing currency.
    """

    material_high_pct: float = 5.0
    material_med_pct: float = 1.0
    abs_high_amount: float = 1000.0
    abs_med_amount: float = 100.0


def cost_severity(
    finding_cost: float,
    scope_cost: float | None,
    config: CostMaterialityConfig | None = None,
    *,
    applicable: bool = True,
) -> tuple[str, float | None]:
    """Map a FinOps finding's spend to ``(severity, cost_pct)`` — cost-relative (FinOps analogue of
    :func:`severity`).

    Args:
        finding_cost: The finding's attributable spend (e.g. waste) in billing currency.
        scope_cost: Total actual spend of the scope in view (the materiality denominator, from the
            Cost Management provider). If ``None``/zero, severity falls back to absolute-amount bands.
        config: Tunable cutoffs.
        applicable: ``False`` when the finding does not apply → ``("none", None)``.

    Returns:
        ``(severity, cost_pct)`` where ``cost_pct`` (finding spend as % of scope spend) is populated
        only in the relative (scope-known) branch, else ``None``.
    """
    cfg = config or CostMaterialityConfig()
    if not applicable:
        return "none", None
    if scope_cost and scope_cost > 0:
        pct = finding_cost / scope_cost * 100.0
        if pct >= cfg.material_high_pct:
            return "high", pct
        if pct >= cfg.material_med_pct:
            return "medium", pct
        return "low", pct
    if finding_cost >= cfg.abs_high_amount:
        return "high", None
    if finding_cost >= cfg.abs_med_amount:
        return "medium", None
    return "low", None

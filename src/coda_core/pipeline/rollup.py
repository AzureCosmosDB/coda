"""Rollup layer (ADR-0007 layer 3): correlate findings within a unit, aggregate across the scope.

Two jobs:
  * **Correlate** — resolve overlaps and explicit related-signal declarations on the *same* unit.
    Rules today: an idle
    container (DX-004) **subsumes** over-provisioning (DX-001) *and* autoscale-max right-sizing
    (DX-011) on that unit — if it's unused, "decommission" is the right call, not "right-size". A
    bursty container (DX-012) subsumes DX-001, and shard-key misalignment (DX-007) subsumes the
    per-query cross-partition finding (DX-002). Subsumed findings are kept but marked
    ``superseded_by`` so they don't double-count or contradict.
  * **Aggregate** — account-level totals (recoverable RU/s, severity counts, abstentions) computed
    only over **actionable** (real, non-superseded) findings.
"""

from __future__ import annotations

from dataclasses import dataclass

from coda_core.pipeline.finding import STATUS_ABSTAINED, STATUS_NOT_DETECTED, Finding
from coda_core.providers.arm import ThroughputOffer


def compute_scope_provisioned_ru(offers: list[ThroughputOffer]) -> float:
    """Total provisioned RU/s of the scope — the capacity materiality denominator (ADR-0012).

    Sums each offer's configured RU/s (manual provisioned, autoscale max). CODA reports
    **capacity, not cost**: this mixes manual and autoscale RU/s, which differ in price per RU/s
    (autoscale ≈1.5× manual) and by region — surfaced as a caveat, not cost-normalized.
    """
    return round(sum(o.provisioned_ru for o in offers), 2)


def _has_same_resource(finding: Finding, candidates: list[Finding]) -> bool:
    """Return whether any candidate has the same canonical structured resource identity."""
    return any(finding.unit.is_same_resource(candidate.unit) for candidate in candidates)


def _apply_supersession(findings: list[Finding]) -> list[Finding]:
    """Apply the existing explicit supersession rules using canonical resource identity."""
    idle = [f for f in findings if f.detection_id == "DX-004" and f.is_actionable()]
    # A bursty container (DX-012 -> autoscale) must not also be told to right-size down (DX-001):
    # cutting the fixed RU/s below the spike would throttle it. Autoscale is the right answer.
    bursty = [f for f in findings if f.detection_id == "DX-012" and f.is_actionable()]
    # Shard-key misalignment (DX-007) is the structural verdict: re-keying subsumes the per-query
    # cross-partition finding (DX-002) on the same container — keep DX-002 but mark it superseded.
    misaligned = [f for f in findings if f.detection_id == "DX-007" and f.is_actionable()]
    out: list[Finding] = []
    for f in findings:
        if f.detection_id == "DX-001" and f.is_actionable() and _has_same_resource(f, idle):
            out.append(f.with_superseded_by("DX-004"))  # idle subsumes over-provisioning
        elif f.detection_id == "DX-011" and f.is_actionable() and _has_same_resource(f, idle):
            out.append(f.with_superseded_by("DX-004"))  # idle subsumes autoscale-max right-sizing
        elif f.detection_id == "DX-001" and f.is_actionable() and _has_same_resource(f, bursty):
            out.append(f.with_superseded_by("DX-012"))  # bursty -> autoscale, not right-size
        elif f.detection_id == "DX-002" and f.is_actionable() and _has_same_resource(f, misaligned):
            out.append(f.with_superseded_by("DX-007"))  # re-key subsumes per-query cross-partition fix
        else:
            out.append(f)
    return out


def _apply_related_signals(findings: list[Finding]) -> list[Finding]:
    """Resolve explicit, unique same-resource parent declarations; invalid declarations fail open."""
    out: list[Finding] = []
    for finding in findings:
        parent_id = finding.related_to
        if (
            not finding.is_actionable()
            or not isinstance(parent_id, str)
            or not parent_id
            or parent_id == finding.detection_id
        ):
            out.append(finding)
            continue
        matching_declarations = [
            candidate
            for candidate in findings
            if candidate.detection_id == finding.detection_id
            and candidate.related_to == parent_id
            and finding.unit.is_same_resource(candidate.unit)
        ]
        if len(matching_declarations) != 1:
            out.append(finding)
            continue
        parents = [
            candidate
            for candidate in findings
            if candidate.detection_id == parent_id
            and candidate.related_to is None
            and candidate.is_actionable()
            and finding.unit.is_same_resource(candidate.unit)
        ]
        out.append(finding.with_related_parent(parent_id) if len(parents) == 1 else finding)
    return out


def correlate(findings: list[Finding]) -> list[Finding]:
    """Apply explicit supersession and related-signal rules, returning a new list."""
    return _apply_related_signals(_apply_supersession(findings))


@dataclass(frozen=True)
class RollupSummary:
    # Backward-compatible field name; counts all unique account/database/container resources scanned.
    units_scanned: int
    detections_run: int
    actionable_findings: int
    abstained: int
    not_detected: int
    severity_counts: dict
    total_recoverable_ru: float
    scope_provisioned_ru: float
    # FinOps dollar surface: summed across actionable customer-bill-derived findings when Cost
    # Management yielded an effective rate. Finding-local regional RU/s never enters recoverable RU/s.
    total_estimated_monthly_savings: float | None = None
    savings_currency: str | None = None

    def as_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


def aggregate(findings: list[Finding], scope_provisioned_ru: float, units_scanned: int) -> RollupSummary:
    """Roll findings up into account-level totals (RU/s + bill-derived $) over actionable findings."""
    actionable = [f for f in findings if f.is_actionable()]
    severity_counts: dict = {}
    total_recoverable = 0.0
    total_savings = 0.0
    savings_currency: str | None = None
    has_savings = False
    for f in actionable:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        if f.recoverable_ru:
            total_recoverable += f.recoverable_ru
        if (
            f.estimated_monthly_savings is not None
            and f.savings_basis == "customer_amortized_bill"
        ):
            total_savings += f.estimated_monthly_savings
            savings_currency = f.savings_currency
            has_savings = True
    return RollupSummary(
        units_scanned=units_scanned,
        detections_run=len(findings),
        actionable_findings=len(actionable),
        abstained=sum(1 for f in findings if f.status == STATUS_ABSTAINED),
        not_detected=sum(1 for f in findings if f.status == STATUS_NOT_DETECTED),
        severity_counts=severity_counts,
        total_recoverable_ru=round(total_recoverable, 2),
        scope_provisioned_ru=scope_provisioned_ru,
        total_estimated_monthly_savings=(round(total_savings, 2) if has_savings else None),
        savings_currency=savings_currency,
    )

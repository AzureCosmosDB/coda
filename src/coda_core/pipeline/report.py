"""The diagnostic report: a deterministic, structured result + a readable renderer.

This is intentionally **not** the LLM-synthesis layer (that comes later, and stays optional).
CODA is diagnose-only: the report states findings + the Agent-Kit rule that remediates each, and
the customer applies the fix via the Agent Kit + their own agent. Findings whose thresholds are
unvalidated are rendered with a clear caveat so nothing looks more certain than it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from coda_core.pipeline.finding import (
    STATUS_ABSTAINED,
    THRESHOLD_PROPOSAL,
    Finding,
)
from coda_core.pipeline.rollup import RollupSummary


@dataclass(frozen=True)
class DiagnosticReport:
    account: str
    resource_group: str
    mode: str
    generated_at: str
    summary: RollupSummary
    findings: list[Finding] = field(default_factory=list)
    # Identifiers that let an agent / the Agent Kit act on the exact resource and find it in the
    # customer's code (the endpoint is what appears in their connection strings / SDK setup).
    account_resource_id: str | None = None
    account_endpoint: str | None = None

    def as_dict(self) -> dict:
        return {
            "account": self.account,
            "resource_group": self.resource_group,
            "account_resource_id": self.account_resource_id,
            "account_endpoint": self.account_endpoint,
            "mode": self.mode,
            "generated_at": self.generated_at,
            "summary": self.summary.as_dict(),
            "findings": [f.as_dict() for f in self.findings],
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Severity presentation (ordering + a plain, scannable label). Internal tokens never reach the page.
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "none": 3}
_SEVERITY_LABEL = {"high": "🔴 High priority", "medium": "🟠 Medium priority",
                   "low": "🟡 Low priority", "none": "Informational"}


def _date_only(iso_ts: str) -> str:
    """The date portion of an ISO timestamp — a full timestamp is noise in a customer header."""
    return iso_ts.split("T", 1)[0] if iso_ts else iso_ts


def _severity_phrase(counts: dict) -> str:
    """'2 high, 6 medium, 1 low' — a readable count, never a raw dict repr."""
    parts = [f"{counts[sev]} {sev}" for sev in ("high", "medium", "low") if counts.get(sev)]
    return ", ".join(parts) if parts else "no"


def _humanize_abstain(summary: str) -> str:
    """Turn an internal abstention reason into one plain phrase (no detector tokens leak out)."""
    text = summary.replace("Insufficient data:", "").strip()
    normalized = text.lower()
    if "log analytics probe failed" in normalized:
        return text or "Log Analytics probe failed"
    text = normalized
    if "diagnostic settings" in text or "cdb" in text or "log analytics" in text:
        return "needs Cosmos diagnostic logs turned on"
    if "no query telemetry" in text:
        return "no query activity recorded in this period"
    if "too_few_requests" in text or "too few" in text:
        return "not enough traffic in this period to judge"
    if "no data-plane telemetry" in text or "no recent data-plane traffic" in text:
        return "no recent data-plane activity in this period"
    if "no_data" in text or "no data" in text:
        return "no metrics in this period"
    if "per-partition storage" in text:
        return "no per-partition storage data available"
    if "per-partition" in text or "per partition" in text:
        return "no per-partition data available"
    if "too young" in text or "age" in text or "created" in text:
        return "resource too new to assess yet"
    return "not enough data to judge"


def _money(amount: float, currency: str | None) -> str:
    return f"~{amount:,.2f} {currency or ''}".rstrip()


def _proposed_cutoff_note(finding: Finding) -> str:
    """Describe the detector's proposed cutoff without implying its implementation is incomplete."""
    cutoffs = []
    for key, value in sorted(finding.evidence.items()):
        if (
            isinstance(value, (str, int, float))
            and ("threshold" in key or "cutoff" in key or key.startswith("min_"))
        ):
            cutoffs.append(f"{key.replace('_', ' ')} = {value}")
    if not cutoffs:
        return (
            "Proposed classification: this detector uses a configuration-based classification "
            "that is still being calibrated."
        )
    return f"Proposed cutoff: {'; '.join(cutoffs)}. Review this cutoff against your workload."


def _related_children(parent: Finding, findings: list[Finding]) -> list[Finding]:
    """Return resolved children for one parent in deterministic customer-visible order."""
    children = [
        finding for finding in findings
        if finding.related_parent == parent.detection_id
        and finding.unit.is_same_resource(parent.unit)
    ]
    return sorted(
        children,
        key=lambda finding: (
            _SEVERITY_RANK.get(finding.severity, 9),
            finding.detection_id,
            finding.title,
            finding.summary,
        ),
    )


def _finding_savings_label(finding: Finding) -> str:
    """Label finding-level savings without conflating bill and public list-price provenance."""
    amount = _money(finding.estimated_monthly_savings or 0.0, finding.savings_currency)
    if finding.savings_basis == "azure_retail_price":
        return f"💰 Azure retail/list-price estimate: {amount}/month"
    if finding.savings_basis == "customer_amortized_bill":
        return f"💰 Customer bill-derived estimate: {amount}/month"
    return f"💰 Savings estimate (provenance unavailable): {amount}/month"


def render_markdown(report: DiagnosticReport) -> str:
    """Render a clean, customer-readable report.

    This is the **human** surface — plain language, scannable, no internal jargon (no ADRs, no raw
    dicts, no 'abstained'/'fleet-validated'). The full structured data (detector ids, evidence,
    thresholds) stays in :meth:`DiagnosticReport.as_dict` for agents and tooling. Detector reference
    codes (e.g. ``DX-004``) are kept as a small tag because the preview feedback loop is keyed on them,
    but they're explained once and never lead.
    """
    s = report.summary
    actionable = sorted(
        (f for f in report.findings if f.is_actionable()),
        key=lambda f: (_SEVERITY_RANK.get(f.severity, 9),
                       -(f.estimated_monthly_savings or 0.0), -(f.recoverable_ru or 0.0),
                       f.detection_id, tuple(part or "" for part in f.unit.canonical_identity())),
    )

    lines = [
        f"# Cosmos DB health & cost report — {report.account}",
        "",
        f"Scanned **{s.units_scanned} resource(s)** in resource group `{report.resource_group}` "
        f"on {_date_only(report.generated_at)}.",
        "",
    ]
    if report.account_endpoint:
        lines += [
            f"**Account:** `{report.account_endpoint}` "
            f"(use the account endpoint + database/container names below to locate a resource in your "
            f"code or in the Azure portal).",
            "",
        ]
    if s.actionable_findings:
        lines.append(
            f"Found **{s.actionable_findings} issue(s) to review** "
            f"({_severity_phrase(s.severity_counts)} priority)."
        )
    else:
        lines.append("**No issues to review** — everything we checked looks healthy. ✅")
    lines.append("")

    # Rollup money contains customer-bill estimates only; retail estimates remain finding-local.
    if s.total_estimated_monthly_savings is not None:
        lines += [
            f"💰 **Estimated customer bill-derived savings: "
            f"{_money(s.total_estimated_monthly_savings, s.savings_currency)}/month** if you act on "
            f"the applicable cost findings below. This is calculated from **your own** Cosmos bill "
            f"— your real, already-discounted rate — and excludes Azure list-price estimates.",
            "",
        ]
    elif s.total_recoverable_ru:
        lines += [
            f"You could reclaim **{s.total_recoverable_ru:,.0f} RU/s** of provisioned capacity "
            f"(out of {s.scope_provisioned_ru:,.0f} RU/s total). To see this as a dollar amount at "
            f"your own discounted rate, grant the tool **Cost Management Reader** and run it again.",
            "",
        ]

    if actionable:
        lines += [
            "_Each finding below has a short reference code (e.g. `DX-004`) — it's just an ID for the "
            "check. Quote it if you send us feedback._",
            "",
        ]

    # Diagnostic-logs callout — plain language, one per distinct fix.
    la_blocked = [f for f in report.findings if f.evidence.get("la_unavailable")]
    if la_blocked:
        by_guidance: dict[str, set[str]] = {}
        for f in la_blocked:
            guidance = f.evidence.get("guidance") or (
                "Turn on Cosmos DB diagnostic settings (resource-specific mode) and send the log "
                "categories to a Log Analytics workspace."
            )
            by_guidance.setdefault(guidance, set()).add(f.detection_id)
        for guidance, ids in by_guidance.items():
            refs = ", ".join(f"`{i}`" for i in sorted(ids))
            lines += [
                f"> ⚠️ **{len(ids)} check(s) couldn't run** — Cosmos diagnostic logs aren't turned on. "
                f"{guidance} _(affected checks: {refs})_",
                "",
            ]

    lines += ["---", "", f"## Issues to review ({len(actionable)})", ""]
    if not actionable:
        lines += ["_Nothing to act on right now._", ""]
    for f in actionable:
        meta = [_SEVERITY_LABEL.get(f.severity, f.severity)]
        if f.estimated_monthly_savings is not None:
            meta.append(_finding_savings_label(f))
        if f.recoverable_ru:
            meta.append(f"{f.recoverable_ru:,.0f} RU/s reclaimable")
        meta.append(f"ref `{f.detection_id}`")
        preview_note = (
            f"  \n_({_proposed_cutoff_note(f)})_"
            if f.threshold_status == THRESHOLD_PROPOSAL
            else ""
        )
        lines += [
            f"### {f.title} — {f.unit.describe()}",
            " · ".join(meta),
            "",
            f"{f.summary}.{preview_note}",
        ]
        if f.recommended_action:
            lines += ["", f"**What to do:** {f.recommended_action}"]
        related = _related_children(f, report.findings)
        if related:
            lines += ["", f"<details><summary>Related signals ({len(related)})</summary>", ""]
            for child in related:
                lines.append(
                    f"- **{child.detection_id} · {child.title}** — severity: {child.severity}; "
                    f"resource: {child.unit.describe()}; summary: {child.summary}"
                )
            lines += ["", "</details>"]
        lines.append("")

    # "Couldn't complete" — grouped BY DETECTOR (named, with its plain reason + how many resources).
    # The superseded/correlated-away findings are intentionally NOT rendered here: the actionable
    # finding that covers them is already shown above, so repeating them adds noise, not value. They
    # remain in the structured as_dict() output (``superseded_by``) for agents that want the full graph.
    abstained = [f for f in report.findings if f.status == STATUS_ABSTAINED]
    if abstained:
        # Group by (detector title, ref code, plain reason) → count of affected resources.
        groups: dict[tuple[str, str, str], int] = {}
        for f in abstained:
            key = (f.title, f.detection_id, _humanize_abstain(f.summary))
            groups[key] = groups.get(key, 0) + 1
        lines += [
            "---", "",
            f"## Checks we couldn't complete ({len(abstained)})", "",
            "_These checks ran but didn't have enough data to give a verdict — listed for transparency; "
            "no action needed unless a fix is called out above._", "",
        ]
        for (title, det_id, reason), n in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][2])):
            scope = f"{n} resource(s)" if n > 1 else "1 resource"
            lines.append(f"- **{title}** ({scope}) — {reason}. _ref `{det_id}`_")
        lines.append("")

    return "\n".join(line for line in lines if line is not None)

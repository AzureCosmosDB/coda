"""Feedback UX — show the user *exactly* what a redacted artifact contains, and make sending it easy.

Privacy posture: CODA **never** transmits anything. Feedback is **opt-in** by construction — this module
only (a) renders a human-readable preview of the PII-safe artifact so the user can see what they'd be
sharing, and (b) prints a one-click link to the pre-filled GitHub issue form. The user still has to
open the link and attach the file themselves; nothing leaves their machine otherwise.
"""

from __future__ import annotations

from collections import Counter

PREVIEW_REPO = "AzureCosmosDB/coda"
FEEDBACK_TEMPLATE = "diagnostic-feedback.yml"


def new_issue_url(repo: str = PREVIEW_REPO, template: str = FEEDBACK_TEMPLATE) -> str:
    """The pre-filled 'Diagnostic feedback' issue-form URL for the preview repo."""
    return f"https://github.com/{repo}/issues/new?template={template}"


def _finding_tally(findings: list[dict]) -> str:
    actionable = [f for f in findings if f.get("status") == "finding" and not f.get("superseded_by")]
    counts = Counter(f"{f['detection_id']}({f['severity']})" for f in actionable)
    if not counts:
        return "none"
    return ", ".join(f"{k}×{v}" if v > 1 else k for k, v in sorted(counts.items()))


def redacted_summary(artifact: dict) -> list[str]:
    """Plain-language summary of what a redacted artifact contains (report or scan)."""
    kind = artifact.get("coda_artifact", "")
    lines = ["This is EXACTLY what would be shared — no account/database/container names, no query "
             "text, no UserAgent, no free text. Only hashed ids + the signal below:"]
    if kind == "redacted-report-v1":
        s = artifact.get("summary", {})
        lines += [
            f"  • Account: {artifact.get('account_h')} (one-way hash) · mode: {artifact.get('mode')}",
            f"  • Resources scanned: {s.get('units_scanned', '?')} · "
            f"actionable findings: {s.get('actionable_findings', '?')} · "
            f"abstained: {s.get('abstained', '?')}",
            f"  • Findings: {_finding_tally(artifact.get('findings', []))}",
            f"  • Recoverable: {s.get('total_recoverable_ru', 0):,} RU/s of "
            f"{s.get('scope_provisioned_ru', 0):,} provisioned",
        ]
    elif kind == "redacted-scan-v1":
        lines += [
            f"  • Subscription: {artifact.get('subscription_h')} (one-way hash) · "
            f"mode: {artifact.get('mode')}",
            f"  • Accounts scanned: {artifact.get('accounts_scanned')} · "
            f"with findings: {artifact.get('accounts_with_findings')} · "
            f"without Log Analytics: {artifact.get('accounts_la_missing')}",
            f"  • Total actionable findings: {artifact.get('total_actionable_findings')} · "
            f"recoverable: {artifact.get('total_recoverable_ru', 0):,} RU/s",
        ]
        fbd = artifact.get("findings_by_detection", {})
        if fbd:
            detail = ", ".join(f"{d}×{i['count']}" for d, i in fbd.items())
            lines.append(f"  • By detector: {detail}")
    else:
        lines.append("  • (unrecognized artifact)")
    return lines


def feedback_block(artifact: dict, redacted_path: str, *, repo: str = PREVIEW_REPO) -> str:
    """The full opt-in feedback block printed after a --redact run."""
    url = new_issue_url(repo)
    lines = [
        "", "=" * 78,
        "FEEDBACK — opt-in. Nothing has been sent; nothing is sent unless you do this.",
        "=" * 78,
        f"Saved a PII-safe summary to:\n  {redacted_path}",
        "",
        *redacted_summary(artifact),
        "",
        "To share it with the CODA team (optional, ~30s):",
        f"  1. Open:  {url}",
        f"  2. Drag the file above into the issue:  {redacted_path}",
        "  3. Tell us what's right / wrong / missing, then Submit.",
        "Only attach the -redacted.json — never the full report.",
        "=" * 78,
    ]
    return "\n".join(lines)


__all__ = ["PREVIEW_REPO", "new_issue_url", "redacted_summary", "feedback_block"]

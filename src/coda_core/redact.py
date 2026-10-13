"""Redaction — turn a CODA report/scan into a PII-safe **research artifact** (signal, not data).

The privacy rule (repository memory): feedback carries the *verdict signal*, never the customer's data.
A raw report contains account/database/container **names**, anonymised-but-sensitive **query text**,
**UserAgent** strings, and free-text summaries that name resources. This module strips all of that and
keeps only what a reviewer needs to judge the diagnostics: **detection id, status, severity, threshold
status, recoverable magnitude, and the methodology cutoffs** — with resource names replaced by salted,
non-reversible hashes (so a reviewer can still see "these 3 findings are on the same container" without
learning which one).

The salt is random per artifact unless supplied, so hashes cannot be correlated across submissions or
reversed by dictionary attack; within one artifact the same resource hashes consistently.
"""

from __future__ import annotations

import hashlib
import secrets

# Evidence keys safe to keep: numeric thresholds / structural facts / generic guidance — never names,
# query text, UserAgent, or free-form detail. Everything else in evidence is dropped (conservative).
_SAFE_EVIDENCE_KEYS = frozenset({
    "band", "root_cause", "abstained", "recoverable_basis", "la_mode", "trigger_statistic",
    "severity_basis", "band_statistic", "guidance", "capability_unavailable", "la_unavailable",
    "bands_pct", "headroom", "min_ru", "thresholds", "trigger_pct",
})

_REPORT_SUMMARY_KEYS = (
    "units_scanned", "detections_run", "actionable_findings", "abstained", "not_detected",
    "severity_counts", "total_recoverable_ru", "scope_provisioned_ru",
)


def _hash(salt: str, *parts: str | None) -> str:
    raw = salt + "|" + "|".join(p or "" for p in parts)
    return "h_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]


# Evidence keys that are billing-sensitive (the customer's actual spend / effective rate) and must be
# DROPPED from the shareable research artifact even though they are numeric — leaking real dollars
# would violate the "signal, not data" rule (ADR-0028 keeps cost in the customer's trust context).
_DROP_EVIDENCE_KEYS = frozenset({
    "estimated_monthly_savings", "savings_currency", "effective_rate_usd_per_ru_month",
    "rate_basis", "amortized_cost", "billed_usage_100rus_hours",
    "storage_snapshot", "retail_pricing",
})


def _redact_evidence(ev: dict) -> dict:
    """Keep numbers/bools and a whitelist of safe keys; recurse dicts; drop names + billing specifics."""
    out: dict = {}
    for k, v in ev.items():
        if k in _DROP_EVIDENCE_KEYS:
            continue  # billing-sensitive: never in a shareable artifact (ADR-0028)
        if isinstance(v, bool) or isinstance(v, (int, float)) or v is None:
            out[k] = v
        elif isinstance(v, dict):
            out[k] = _redact_evidence(v)
        elif k in _SAFE_EVIDENCE_KEYS:
            out[k] = v  # safe string / list (e.g. guidance, capability ids, threshold maps)
        # else: drop (QueryText, UserAgent, worst_shape, monopolizer, victim, detail, error, note, ...)
    return out


def redact_finding(f: dict, salt: str) -> dict:
    u = f["unit"]
    return {
        "detection_id": f["detection_id"],
        "title": f.get("title"),                 # generic detector name — no PII
        "status": f["status"],
        "severity": f["severity"],
        "threshold_status": f.get("threshold_status"),
        "recoverable_ru": f.get("recoverable_ru"),
        "materiality_pct": f.get("materiality_pct"),
        "agent_kit_rule": f.get("agent_kit_rule"),
        "superseded_by": f.get("superseded_by"),
        "unit": {
            "level": u.get("level"),
            "account_h": _hash(salt, u.get("account")),
            "database_h": _hash(salt, u.get("account"), u.get("database")) if u.get("database") else None,
            "container_h": (_hash(salt, u.get("account"), u.get("database"), u.get("container"))
                            if u.get("container") else None),
        },
        "evidence": _redact_evidence(f.get("evidence", {})),
        # Deliberately dropped: summary, recommended_action (free text naming resources / queries / SDKs).
    }


def redact_report(report: dict, *, salt: str | None = None) -> dict:
    """Redact a single-account ``DiagnosticReport.as_dict()`` into a research artifact."""
    salt = salt or secrets.token_hex(8)
    summary = report.get("summary", {})
    return {
        "coda_artifact": "redacted-report-v1",
        "generated_at": report.get("generated_at"),
        "mode": report.get("mode"),
        "account_h": _hash(salt, report.get("account")),
        "summary": {k: summary[k] for k in _REPORT_SUMMARY_KEYS if k in summary},
        "findings": [redact_finding(f, salt) for f in report.get("findings", [])],
    }


def redact_scan(agg: dict, *, salt: str | None = None) -> dict:
    """Redact a fleet-scan aggregate (``FleetScanResult.aggregate()``) into a research artifact."""
    salt = salt or secrets.token_hex(8)
    keep = (
        "mode", "generated_at", "accounts_scanned", "accounts_errored", "accounts_timed_out",
        "accounts_with_findings", "accounts_la_missing", "total_actionable_findings",
        "total_recoverable_ru", "total_abstained", "findings_by_detection", "elapsed_s",
    )
    out = {k: agg[k] for k in keep if k in agg}
    out["coda_artifact"] = "redacted-scan-v1"
    out["subscription_h"] = _hash(salt, agg.get("subscription"))
    out["top_findings"] = [
        {"detection_id": t["detection_id"], "severity": t["severity"],
         "recoverable_ru": t.get("recoverable_ru"), "account_h": _hash(salt, t.get("account"))}
        for t in agg.get("top_findings", [])
    ]
    out["per_account"] = [
        {"account_h": _hash(salt, a.get("account")), "units_scanned": a.get("units_scanned"),
         "actionable": a.get("actionable"), "abstained": a.get("abstained"),
         "la_missing": a.get("la_missing"), "recoverable_ru": a.get("recoverable_ru"),
         "status": a.get("status")}
        for a in agg.get("per_account", [])
    ]
    return out


__all__ = ["redact_report", "redact_scan", "redact_finding"]

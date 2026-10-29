"""MCP tool logic — pure functions an agent surface (or anything) can call.

These are the *capabilities* the MCP server exposes, kept free of any ``mcp`` dependency so they are
unit-testable and reusable: ``coda_core.mcp_server`` is a thin adapter that registers
these as tools. Every function returns plain JSON-serialisable data — the same contract the CLI emits.

The local web and MCP surfaces use this and the core ``scan`` / ``run_diagnostics``; there is
no surface-specific detection logic.
"""

from __future__ import annotations

from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path

from coda_core.pipeline import default_eval_window, run_diagnostics
from coda_core.pipeline.registry import (
    ACCOUNT_REGISTRY,
    DATABASE_REGISTRY,
    INVENTORY_REGISTRY,
    REGISTRY,
    SERVERLESS_REGISTRY,
    threshold_status_for,
)
from coda_core.providers.arm import ArmProvider
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.cost_management import CostManagementProvider
from coda_core.providers.log_analytics import LogAnalyticsProvider
from coda_core.providers.retail_prices import RetailPricesProvider
from coda_core.redact import redact_report, redact_scan
from coda_core.feedback import new_issue_url, redacted_summary
from coda_core.scan import scan, shallow_scan, shallow_scan_account

def _credential(credential=None):
    if credential is not None:
        return credential
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential()


def list_detectors() -> dict:
    """The detector catalog: id, title, scope(s), threshold status, and required capabilities.

    Lets an agent answer "what does CODA check for?" without running anything.
    """
    by_id: dict[str, dict] = {}
    for reg, scope in (
        (REGISTRY, "container"), (ACCOUNT_REGISTRY, "account"),
        (DATABASE_REGISTRY, "database"), (SERVERLESS_REGISTRY, "serverless"),
        (INVENTORY_REGISTRY, "container"),
    ):
        for a in reg:
            entry = by_id.setdefault(a.detection_id, {
                "detection_id": a.detection_id, "title": a.title, "scopes": set(),
                "threshold_status": threshold_status_for(a.detection_id),
                "requires": sorted(getattr(a, "requires", frozenset())),
            })
            entry["scopes"].add(scope)
            entry["requires"] = sorted(set(entry["requires"]) | set(getattr(a, "requires", frozenset())))
    detectors = [{**v, "scopes": sorted(v["scopes"])} for v in by_id.values()]
    detectors.sort(key=lambda d: d["detection_id"])
    return {"count": len(detectors), "detectors": detectors}


def _methodology_root() -> Traversable:
    """Prefer installed resources; support only the known editable/source public-doc layout."""
    packaged = files("coda_core").joinpath("detector_methodology")
    if packaged.is_dir():
        return packaged
    package = Path(__file__).resolve().parent
    checkout = package.parent.parent
    if package.parent.name == "src" and (checkout / "pyproject.toml").is_file():
        return checkout / "docs" / "detector-methodology"
    return packaged


def explain_finding(detection_id: str) -> dict:
    """Explain a registered detector offline using the methodology shipped with this engine."""
    did = detection_id.strip().upper()
    known = {item["detection_id"] for item in list_detectors()["detectors"]}
    if did not in known:
        return {"detection_id": did, "found": False,
                "message": f"Unknown detector {did}; use list_detectors for supported IDs."}
    filename = f"{did.lower()}.md"
    try:
        content = _methodology_root().joinpath(filename).read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(
            f"CODA methodology for {did} could not be read. "
            "Reinstall the verified CODA wheel, or restore its public methodology source files."
        ) from exc
    if not content.startswith(f"# {did}:"):
        raise RuntimeError(f"CODA methodology for {did} is invalid; reinstall the verified wheel.")
    return {"detection_id": did, "found": True,
            "doc_path": f"docs/detector-methodology/{filename}", "methodology": content}


def _feedback_payload(redacted: dict) -> dict:
    """Wrap a redacted artifact with a human preview + the feedback link for the agent to relay."""
    return {
        "redacted": redacted,
        "feedback_preview": redacted_summary(redacted),
        "feedback_url": new_issue_url(),
        "note": "PII-safe (resource names hashed; no query text / UserAgent / prose). To send "
                "feedback: open feedback_url and paste the 'redacted' JSON into the issue, then "
                "describe what's right or wrong.",
    }


def diagnose_account(
    subscription: str, resource_group: str, account: str, *, mode: str = "production",
    eval_hours: int | None = None, redact: bool = False, credential=None,
    unit_concurrency: int | None = None,
) -> dict:
    """Diagnose ONE account in depth and return the full structured report (drill-in).

    With ``redact=True`` returns a PII-safe artifact (+ feedback link) instead of the raw report —
    use this when an agent should help the user submit feedback without exposing resource names.
    """
    cred = _credential(credential)
    arm = ArmProvider(cred, subscription)
    metrics = AzureMonitorMetricsProvider(cred)
    la = LogAnalyticsProvider(cred)
    cost = CostManagementProvider(cred, subscription)
    retail_prices = RetailPricesProvider()
    eval_window = default_eval_window(hours=eval_hours) if eval_hours else None
    report = run_diagnostics(metrics, arm, resource_group, account, mode=mode,
                             eval_window=eval_window, la=la, cost=cost,
                             retail_prices=retail_prices,
                             unit_concurrency=unit_concurrency)
    d = report.as_dict()
    return _feedback_payload(redact_report(d)) if redact else d


def scan_subscription(
    subscription: str, *, resource_groups=None, accounts=None, mode: str = "production",
    concurrency: int = 8, per_account_timeout: float = 120.0, limit: int | None = None,
    redact: bool = False, credential=None,
) -> dict:
    """Scan a subscription (breadth) and return the aggregate summary (findings by detector + per-account).

    The agent's "what should I know about across my whole subscription?" entry point. With
    ``redact=True`` returns a PII-safe artifact (+ feedback link) for submitting feedback.
    """
    cred = _credential(credential)
    result = scan(cred, subscription, resource_groups=resource_groups, accounts=accounts, mode=mode,
                  concurrency=concurrency, per_account_timeout=per_account_timeout, limit=limit)
    agg = result.aggregate()
    return _feedback_payload(redact_scan(agg)) if redact else agg


def scan_subscription_shallow(
    subscription: str, *, resource_groups=None, accounts=None, window_hours: int = 24,
    concurrency: int = 24, limit: int | None = None, credential=None,
) -> dict:
    """Tier-1 subscription health grid: fast, account-level signals with **no Log Analytics**.

    The "outer layer of the onion" — reads a few account-scope metrics per account (throttle rate,
    peak partition saturation) so a large subscription returns in seconds, and surfaces the problem
    accounts to drill into. Deep per-account analysis (Tier-2 metrics/ARM, Tier-3 Log Analytics root
    cause) is done by ``diagnose_account`` on a flagged account.
    """
    cred = _credential(credential)
    result = shallow_scan(cred, subscription, resource_groups=resource_groups, accounts=accounts,
                          window_hours=window_hours, concurrency=concurrency, limit=limit)
    return result.aggregate()


def diagnose_account_shallow(
    subscription: str, resource_group: str, account: str, *, window_hours: int = 24, credential=None,
) -> dict:
    """Fast, shallow (Tier-1) health signal for ONE account — account-level metrics only.

    The account-scoped twin of :func:`scan_subscription_shallow`: peak partition saturation + 429 rate,
    **no Log Analytics and no per-container work**, returning in ~1 s. Use it as a quick "is this
    account OK?" check; call :func:`diagnose_account` for the full applicable-detector report.
    """
    cred = _credential(credential)
    return shallow_scan_account(cred, subscription, resource_group, account,
                                window_hours=window_hours).as_row()


__all__ = ["list_detectors", "explain_finding", "diagnose_account", "diagnose_account_shallow",
           "scan_subscription", "scan_subscription_shallow"]

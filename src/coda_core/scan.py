"""Fleet scan — diagnose many Cosmos accounts in a subscription, concurrently and resiliently.

This is the **shared core** behind every breadth surface: the customer CLI's "scan my subscription",
and (next) the MCP server's ``scan_subscription`` tool both call :func:`scan`. It wraps the same
per-account pipeline (:func:`run_diagnostics`) the single-account path uses — no separate logic.

Hardening (learned from a real 2,982-account run that hung on one account):
  * **per-account timeout** — a single slow/hung account can't stall the whole scan,
  * **concurrency** — accounts are diagnosed in parallel (bounded pool),
  * **resilience** — an account the caller can't read (403) or that errors/times out is recorded and
    skipped, never aborting the scan,
  * **progress** — an optional callback reports completion as it happens.

Providers are constructed **per worker** (not shared across threads) since the Azure SDK clients are not
guaranteed thread-safe; the credential is shared (azure-identity handles concurrent token use).
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from azure.mgmt.cosmosdb import CosmosDBManagementClient

from coda_core.pipeline import default_eval_window, run_diagnostics
from coda_core.providers.arm import ArmProvider
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow
from coda_core.providers.cost_management import CostManagementProvider
from coda_core.providers.log_analytics import LogAnalyticsProvider
from coda_core.providers.retail_prices import RetailPricesProvider

NOSQL_KIND = "GlobalDocumentDB"


def list_accounts(
    credential, subscription: str, *, resource_groups=None, accounts=None, nosql_only: bool = True,
) -> list[tuple[str, str]]:
    """Enumerate ``(resource_group, account)`` pairs in the subscription, optionally filtered.

    When ``resource_groups`` is given we query **per resource group** (fast) rather than paging every
    account in the subscription and filtering — the latter is minutes-slow on large subscriptions.
    """
    accs = {a.lower() for a in accounts} if accounts else None
    client = CosmosDBManagementClient(credential, subscription)

    def _keep(name: str, kind: str) -> bool:
        if accs and name.lower() not in accs:
            return False
        return not (nosql_only and kind != NOSQL_KIND)

    out: list[tuple[str, str]] = []
    if resource_groups:
        for rg in resource_groups:
            for a in client.database_accounts.list_by_resource_group(rg):
                if _keep(a.name, a.kind):
                    out.append((rg, a.name))
    else:
        for a in client.database_accounts.list():
            rg = a.id.split("/resourceGroups/")[1].split("/")[0]
            if _keep(a.name, a.kind):
                out.append((rg, a.name))
    return out


@dataclass
class AccountScanResult:
    """One account's scan outcome (a thin projection over its full report + the report itself)."""

    resource_group: str
    account: str
    units_scanned: int = 0
    actionable: int = 0
    abstained: int = 0
    la_missing: bool = False
    recoverable_ru: float = 0.0
    status: str = "ok"               # ok | error | timeout
    error: str | None = None
    report: dict | None = None       # full DiagnosticReport.as_dict() (for artifact writing / drill-in)

    def as_row(self) -> dict:
        return {"resource_group": self.resource_group, "account": self.account,
                "units_scanned": self.units_scanned, "actionable": self.actionable,
                "abstained": self.abstained, "la_missing": self.la_missing,
                "recoverable_ru": round(self.recoverable_ru), "status": self.status,
                "error": self.error,
                **({"cost_estimate_issue": self.report["cost_estimate_issue"]}
                   if self.report and self.report.get("cost_estimate_issue") else {})}


@dataclass
class FleetScanResult:
    """The aggregate of a fleet scan: per-account results + a roll-up."""

    subscription: str
    mode: str
    generated_at: str
    accounts: list[AccountScanResult] = field(default_factory=list)
    elapsed_s: float = 0.0

    def aggregate(self) -> dict:
        ok = [a for a in self.accounts if a.status == "ok"]
        det: Counter = Counter()
        sev_by_det: dict[str, Counter] = {}
        top: list[dict] = []
        for a in ok:
            for f in (a.report or {}).get("findings", []):
                if f["status"] == "finding" and not f.get("superseded_by"):
                    det[f["detection_id"]] += 1
                    sev_by_det.setdefault(f["detection_id"], Counter())[f["severity"]] += 1
                    top.append({"account": a.account, "resource_group": a.resource_group,
                                "detection_id": f["detection_id"], "severity": f["severity"],
                                "summary": f["summary"], "recoverable_ru": f.get("recoverable_ru")})
        return {
            "subscription": self.subscription, "mode": self.mode, "generated_at": self.generated_at,
            "accounts_scanned": len(ok),
            "accounts_errored": sum(1 for a in self.accounts if a.status == "error"),
            "accounts_timed_out": sum(1 for a in self.accounts if a.status == "timeout"),
            "accounts_with_findings": sum(1 for a in ok if a.actionable > 0),
            "accounts_la_missing": sum(1 for a in ok if a.la_missing),
            "total_actionable_findings": int(sum(det.values())),
            "total_recoverable_ru": round(sum(a.recoverable_ru for a in ok)),
            "total_abstained": sum(a.abstained for a in ok),
            "findings_by_detection": {k: {"count": v, "by_severity": dict(sev_by_det.get(k, {}))}
                                      for k, v in det.most_common()},
            "elapsed_s": self.elapsed_s,
            "top_findings": top,
            "per_account": [a.as_row() for a in self.accounts],
        }


def _run_with_timeout(fn, timeout_s: float):
    """Run ``fn`` in a daemon thread, returning ``(result, error)``; a hang yields a TimeoutError.

    The blocking Azure SDK calls can't be force-cancelled, so on timeout we abandon the daemon thread
    (it dies with the process) and move on — exactly what keeps one bad account from stalling the scan.
    """
    box: dict = {}

    def target() -> None:
        try:
            box["result"] = fn()
        except Exception as exc:  # noqa: BLE001 - carry any error back to the caller
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        return None, TimeoutError(f"diagnosis exceeded {timeout_s}s")
    return box.get("result"), box.get("error")


def _to_result(rg: str, name: str, report, error) -> AccountScanResult:
    if error is not None:
        status = "timeout" if isinstance(error, TimeoutError) else "error"
        return AccountScanResult(rg, name, status=status, error=f"{type(error).__name__}: {error}")
    actionable = [f for f in report.findings if f.is_actionable()]
    abstained = [f for f in report.findings if f.status == "abstained"]
    return AccountScanResult(
        rg, name, units_scanned=report.summary.units_scanned, actionable=len(actionable),
        abstained=len(abstained),
        la_missing=any(f.evidence.get("la_unavailable") for f in report.findings),
        recoverable_ru=sum(f.recoverable_ru or 0 for f in actionable),
        status="ok", report=report.as_dict(),
    )


def scan(
    credential, subscription: str, *, resource_groups=None, accounts=None, mode: str = "production",
    concurrency: int = 8, per_account_timeout: float = 120.0, eval_hours=None, limit=None,
    progress=None,
) -> FleetScanResult:
    """Diagnose every (filtered) Cosmos account in ``subscription`` concurrently and resiliently.

    Args:
        resource_groups / accounts: optional allow-lists (case-insensitive) to narrow scope.
        mode: ``production`` (honest long windows + age guard) or ``eval`` (recent window, no age guard).
        concurrency: max accounts diagnosed in parallel.
        per_account_timeout: seconds before an account is recorded as ``timeout`` and skipped.
        limit: cap the number of accounts (sampling).
        progress: optional ``callable(done, total, account_result)`` invoked as each account completes.
    """
    targets = list_accounts(credential, subscription, resource_groups=resource_groups,
                            accounts=accounts)
    if limit:
        targets = targets[:limit]
    eval_window = default_eval_window(hours=eval_hours) if eval_hours else None

    def _diagnose(rg: str, name: str):
        # Per-worker providers (SDK clients aren't guaranteed thread-safe); credential is shared.
        arm = ArmProvider(credential, subscription)
        metrics = AzureMonitorMetricsProvider(credential)
        la = LogAnalyticsProvider(credential)
        cost = CostManagementProvider(credential, subscription)
        retail_prices = RetailPricesProvider()
        # Fleet scan already parallelizes accounts; keep per-account unit work serial here to avoid
        # multiplicative worker fan-out. Single-account diagnose uses run_diagnostics' default pool.
        return run_diagnostics(metrics, arm, rg, name, mode=mode, eval_window=eval_window,
                               la=la, cost=cost, retail_prices=retail_prices, unit_concurrency=1)

    result = FleetScanResult(subscription, mode, datetime.now(timezone.utc).isoformat())
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        fut_map = {
            ex.submit(_run_with_timeout, (lambda rg=rg, n=n: _diagnose(rg, n)), per_account_timeout):
                (rg, n)
            for rg, n in targets
        }
        done = 0
        for fut in concurrent.futures.as_completed(fut_map):
            rg, name = fut_map[fut]
            report, error = fut.result()
            acct = _to_result(rg, name, report, error)
            result.accounts.append(acct)
            done += 1
            if progress:
                progress(done, len(targets), acct)
    result.elapsed_s = round(time.time() - t0, 1)
    return result


# --- Shallow (Tier-1) subscription scan ------------------------------------------------------------
# The deep ``scan`` above runs the full per-account pipeline (metrics + ARM + Log Analytics) and is far
# too slow for a subscription health grid — a 136-account subscription takes ~14 min and hammers the LA
# workspace 136x. The shallow scan is the first "layer of the onion": it reads only a few *account-level*
# Azure Monitor metrics per account (no per-container fan-out, no Log Analytics), classifies a quick
# health signal, and surfaces problem accounts to drill into. It does NOT replace the deep diagnosis —
# it routes the customer to it (Tier-2 = metrics/ARM, Tier-3 = Log Analytics root cause) per account.

SHALLOW_THROTTLE_WARN = 1.0   # % of requests throttled (429) to warn
SHALLOW_THROTTLE_HIGH = 5.0   # % throttled -> high severity
SHALLOW_SAT_WARN = 80.0       # peak NormalizedRUConsumption % (hottest partition) to warn
SHALLOW_SAT_HIGH = 95.0       # peak saturation % -> high severity
SHALLOW_MIN_REQUESTS = 100    # ignore throttle noise below this request count


def classify_shallow(
    total_requests: float, throttle_pct: float, peak_saturation_pct: float
) -> tuple[str, str, str]:
    """Map account-level signals to ``(status, severity, reason)`` — pure and unit-tested.

    status: ``quiet`` | ``healthy`` | ``throttling`` | ``saturated``; severity: ``none`` | ``medium`` |
    ``high``. Deliberately conservative: throttling is ignored below ``SHALLOW_MIN_REQUESTS`` so a
    handful of 429s on an almost-idle account can't masquerade as a problem.
    """
    throttling = throttle_pct >= SHALLOW_THROTTLE_WARN and total_requests >= SHALLOW_MIN_REQUESTS
    saturated = peak_saturation_pct >= SHALLOW_SAT_WARN
    if total_requests <= 0 and peak_saturation_pct <= 0:
        return "quiet", "none", "no requests in window"
    if not throttling and not saturated:
        return "healthy", "none", "no throttling or saturation"
    parts = []
    if throttling:
        parts.append(f"{throttle_pct:.1f}% throttled over {total_requests:,.0f} requests")
    if saturated:
        parts.append(f"peak {peak_saturation_pct:.0f}% partition saturation")
    high = (throttle_pct >= SHALLOW_THROTTLE_HIGH or peak_saturation_pct >= SHALLOW_SAT_HIGH
            or (throttling and saturated))
    status = "throttling" if throttling else "saturated"
    return status, ("high" if high else "medium"), "; ".join(parts)


@dataclass
class ShallowAccountResult:
    """One account's shallow (Tier-1) health signal — a thin, drill-in-able projection."""

    resource_group: str
    account: str
    status: str = "no_data"
    severity: str = "none"
    total_requests: float = 0.0
    throttle_pct: float = 0.0
    peak_saturation_pct: float = 0.0
    reason: str = ""
    error: str | None = None

    def as_row(self) -> dict:
        return {"resource_group": self.resource_group, "account": self.account,
                "status": self.status, "severity": self.severity,
                "total_requests": round(self.total_requests),
                "throttle_pct": round(self.throttle_pct, 2),
                "peak_saturation_pct": round(self.peak_saturation_pct),
                "reason": self.reason, "error": self.error}


@dataclass
class ShallowScanResult:
    """Aggregate of a shallow subscription scan: per-account signals + a roll-up."""

    subscription: str
    generated_at: str
    accounts: list[ShallowAccountResult] = field(default_factory=list)
    elapsed_s: float = 0.0

    def aggregate(self) -> dict:
        ok = [a for a in self.accounts if a.error is None]
        sev = Counter(a.severity for a in ok)
        status = Counter(a.status for a in ok)
        problems = sorted(
            (a for a in ok if a.severity in ("high", "medium")),
            key=lambda a: (0 if a.severity == "high" else 1, -a.throttle_pct, -a.peak_saturation_pct),
        )
        return {
            "subscription": self.subscription, "generated_at": self.generated_at, "mode": "shallow",
            "accounts_scanned": len(ok),
            "accounts_errored": sum(1 for a in self.accounts if a.error is not None),
            "problem_accounts": len(problems),
            "by_severity": {"high": sev.get("high", 0), "medium": sev.get("medium", 0)},
            "by_status": dict(status),
            "elapsed_s": self.elapsed_s,
            "problems": [a.as_row() for a in problems],
            "per_account": [a.as_row() for a in self.accounts],
        }


def _shallow_probe_account(
    metrics: AzureMonitorMetricsProvider, subscription: str, rg: str, name: str, window: TimeWindow
) -> ShallowAccountResult:
    """Read a few account-level metrics (no per-container, no Log Analytics) and classify health.

    Uses NormalizedRUConsumption (peak partition saturation) and the 429 rate — both safe for serverless
    (which emits no provisioned-throughput metric, avoiding the serverless false-positive class). The
    ``metrics`` provider is shared across workers: azure-identity credentials are thread-safe and cache
    tokens, so one shared client avoids a per-account Azure-CLI token storm under high concurrency.
    """
    rid = (f"/subscriptions/{subscription}/resourceGroups/{rg}"
           f"/providers/Microsoft.DocumentDB/databaseAccounts/{name}")
    # One split call yields both total requests and the 429 count (validated to equal plain Count),
    # so each account is 2 metric calls, not 3.
    by_status = metrics.get_metric_split(
        rid, "TotalRequests", window, split_dimension="StatusCode", aggregation="Count")
    total = sum(sum(p.value for p in s.points) for s in by_status.values())
    throttled = sum(sum(p.value for p in s.points)
                    for code, s in by_status.items() if str(code) == "429")
    sat_points = metrics.get_metric(
        rid, "NormalizedRUConsumption", window, aggregation="Maximum").points
    peak_sat = max((p.value for p in sat_points), default=0.0)
    throttle_pct = (100.0 * throttled / total) if total else 0.0
    st, sev, reason = classify_shallow(total, throttle_pct, peak_sat)
    return ShallowAccountResult(rg, name, status=st, severity=sev, total_requests=total,
                                throttle_pct=throttle_pct, peak_saturation_pct=peak_sat, reason=reason)


def shallow_scan(
    credential, subscription: str, *, resource_groups=None, accounts=None, window_hours: int = 24,
    concurrency: int = 32, per_account_timeout: float = 20.0, limit=None, progress=None,
) -> ShallowScanResult:
    """Tier-1 subscription health grid: fast, account-level, **no Log Analytics**.

    Reads only account-scope Azure Monitor metrics per account (a few calls each), so a large
    subscription returns in seconds instead of minutes. A hung/unreadable account is recorded and
    skipped (per-account timeout), never stalling the grid. Drill into a flagged account for the deep
    metrics/ARM diagnosis (Tier-2) and Log Analytics root cause (Tier-3).
    """
    targets = list_accounts(credential, subscription, resource_groups=resource_groups,
                            accounts=accounts)
    if limit:
        targets = targets[:limit]
    end = datetime.now(timezone.utc)
    window = TimeWindow(end - timedelta(hours=window_hours), end, timedelta(hours=1))
    # One shared metrics client for the whole scan: azure-identity credentials are thread-safe and
    # cache tokens, so a single client acquires the token once instead of every worker shelling out to
    # the Azure CLI at once (which fails under high concurrency).
    metrics = AzureMonitorMetricsProvider(credential)
    # Warm the shared credential's token once (best effort) so the worker burst below reuses the cached
    # token instead of every thread shelling out to the Azure CLI at once (which fails under load).
    if targets:
        try:
            _wrg, _wn = targets[0]
            metrics.get_metric(
                f"/subscriptions/{subscription}/resourceGroups/{_wrg}"
                f"/providers/Microsoft.DocumentDB/databaseAccounts/{_wn}",
                "TotalRequests", window, aggregation="Count")
        except Exception:  # noqa: BLE001 - warm-up is best effort; the real read happens in the pool
            pass
    result = ShallowScanResult(subscription, end.isoformat())
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        fut_map = {
            ex.submit(
                _run_with_timeout,
                (lambda rg=rg, n=n: _shallow_probe_account(metrics, subscription, rg, n, window)),
                per_account_timeout,
            ): (rg, n)
            for rg, n in targets
        }
        done = 0
        for fut in concurrent.futures.as_completed(fut_map):
            rg, name = fut_map[fut]
            res, err = fut.result()
            if err is not None:
                status = "timeout" if isinstance(err, TimeoutError) else "error"
                acct = ShallowAccountResult(rg, name, status=status,
                                            error=f"{type(err).__name__}: {err}")
            else:
                acct = res
            result.accounts.append(acct)
            done += 1
            if progress:
                progress(done, len(targets), acct)
    result.elapsed_s = round(time.time() - t0, 1)
    return result


def shallow_scan_account(
    credential, subscription: str, resource_group: str, account: str, *, window_hours: int = 24,
    metrics: AzureMonitorMetricsProvider | None = None,
) -> ShallowAccountResult:
    """Tier-1 health signal for a **single** account — the same account-level metrics as
    :func:`shallow_scan` (429 rate + peak partition saturation), for one account, in ~1 s.

    The fast "is this account OK?" check before committing to a deep :func:`run_diagnostics`. No Log
    Analytics, no per-container fan-out. Errors are returned as an ``error`` result, never raised.
    """
    end = datetime.now(timezone.utc)
    window = TimeWindow(end - timedelta(hours=window_hours), end, timedelta(hours=1))
    provider = metrics or AzureMonitorMetricsProvider(credential)
    try:
        return _shallow_probe_account(provider, subscription, resource_group, account, window)
    except Exception as exc:  # noqa: BLE001 - one account; surface as an error result, don't raise
        return ShallowAccountResult(resource_group, account, status="error",
                                    error=f"{type(exc).__name__}: {exc}")


__all__ = ["scan", "list_accounts", "AccountScanResult", "FleetScanResult", "NOSQL_KIND",
           "shallow_scan", "shallow_scan_account", "classify_shallow", "ShallowAccountResult",
           "ShallowScanResult"]

"""Preflight capability checks — verify the current credential can do everything CODA needs.

CODA is read-only and diagnose-only (guardrail), so these **probe-by-attempt** checks confirm
READ access to each data source a diagnosis uses, plus data-availability **preconditions** —
failing fast with a clear "grant <role> on <scope>" message instead of a mid-run 403. Two kinds:
  * ``authz``        — can the credential read this source? (403 => missing role)
  * ``precondition`` — is the data even available? (e.g. diagnostic settings enabled)

The probes attempt the minimal real read (no RBAC enumeration needed) and classify the result.
We do **not** probe data-plane (document) read — CODA never reads customer documents.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from azure.core.credentials import TokenCredential
from azure.core.exceptions import ClientAuthenticationError

from coda_core.providers.arm import ArmProvider
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow
from coda_core.providers.cost_management import CostManagementProvider
from coda_core.providers.log_analytics import LogAnalyticsProvider

OK = "ok"
FORBIDDEN = "forbidden"
NOT_FOUND = "not_found"
AUTH_FAILED = "auth_failed"
NO_DATA = "no_data"
ERROR = "error"


def classify_exception(exc: Exception) -> str:
    """Map an Azure SDK exception to a check status (duck-typed on ``status_code``)."""
    if isinstance(exc, ClientAuthenticationError):
        return AUTH_FAILED
    code = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if code == 403:
        return FORBIDDEN
    if code == 404:
        return NOT_FOUND
    return ERROR


@dataclass(frozen=True)
class CheckResult:
    capability: str
    kind: str  # "authz" | "precondition"
    status: str
    scope: str
    detail: str = ""
    fix_hint: str = ""

    @property
    def passed(self) -> bool:
        return self.status == OK

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class PreflightTarget:
    subscription: str
    resource_group: str
    account: str
    account_resource_id: str
    workspace_id: str | None = None  # Log Analytics workspace *customer id* (GUID)


def _arm_read(cred: TokenCredential, t: PreflightTarget) -> CheckResult:
    try:
        ArmProvider(cred, t.subscription).get_account(t.resource_group, t.account)
        return CheckResult("ARM control-plane read", "authz", OK, t.account)
    except Exception as exc:  # noqa: BLE001 - probe: classify, don't crash
        return CheckResult(
            "ARM control-plane read", "authz", classify_exception(exc), t.account,
            detail=str(exc)[:200], fix_hint="Grant 'Reader' on the Cosmos DB account.",
        )


def _metrics_read(cred: TokenCredential, t: PreflightTarget) -> CheckResult:
    now = datetime.now(timezone.utc)
    window = TimeWindow(now - timedelta(minutes=10), now, timedelta(minutes=1))
    try:
        AzureMonitorMetricsProvider(cred).get_metric(
            t.account_resource_id, "NormalizedRUConsumption", window, aggregation="Maximum"
        )
        return CheckResult("Azure Monitor metrics read", "authz", OK, t.account)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "Azure Monitor metrics read", "authz", classify_exception(exc), t.account,
            detail=str(exc)[:200], fix_hint="Grant 'Monitoring Reader' on the account.",
        )


def _cost_management_read(cred: TokenCredential, t: PreflightTarget) -> CheckResult:
    """Probe Cost Management read (FinOps). A small recent actual-cost query; 403 => missing role."""
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=2)
    try:
        CostManagementProvider(cred, t.subscription).actual_cost(start, end)
        return CheckResult("Cost Management read", "authz", OK, f"subscription {t.subscription}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "Cost Management read", "authz", classify_exception(exc), f"subscription {t.subscription}",
            detail=str(exc)[:200], fix_hint="Grant 'Cost Management Reader' on the subscription.",
        )


def _la_read(cred: TokenCredential, t: PreflightTarget) -> CheckResult:
    now = datetime.now(timezone.utc)
    try:
        LogAnalyticsProvider(cred).query(t.workspace_id, "print 1", (now - timedelta(minutes=10), now))
        return CheckResult("Log Analytics read", "authz", OK, f"workspace {t.workspace_id}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "Log Analytics read", "authz", classify_exception(exc), f"workspace {t.workspace_id}",
            detail=str(exc)[:200], fix_hint="Grant 'Log Analytics Reader' on the workspace.",
        )


def _cdb_logs_present(cred: TokenCredential, t: PreflightTarget) -> CheckResult:
    now = datetime.now(timezone.utc)
    span = (now - timedelta(days=1), now)
    try:
        rows = LogAnalyticsProvider(cred).query(
            t.workspace_id, "CDBDataPlaneRequests | summarize n = count()", span
        )
        n = int(rows[0].get("n")) if rows and rows[0].get("n") is not None else 0
        if n > 0:
            return CheckResult(
                "CDB diagnostic logs present", "precondition", OK,
                f"workspace {t.workspace_id}", detail=f"{n} rows in last 1d",
            )
        status, detail = NO_DATA, "no CDBDataPlaneRequests rows in last 1d"
    except Exception as exc:  # noqa: BLE001 - table-not-found etc. => precondition not met
        status, detail = NO_DATA, str(exc)[:200]
    return CheckResult(
        "CDB diagnostic logs present", "precondition", status, f"workspace {t.workspace_id}",
        detail=detail,
        fix_hint="Enable diagnostic settings exporting CDB* logs to this Log Analytics workspace.",
    )


def run_preflight(credential: TokenCredential, target: PreflightTarget) -> list[CheckResult]:
    """Run all capability checks for one target. Workspace checks run only if a workspace is set."""
    results = [
        _arm_read(credential, target),
        _metrics_read(credential, target),
        _cost_management_read(credential, target),
    ]
    if target.workspace_id:
        results += [_la_read(credential, target), _cdb_logs_present(credential, target)]
    return results

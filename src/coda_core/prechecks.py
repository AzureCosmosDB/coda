"""Read-only prerequisite probes with context-specific copy-only remediation."""

from __future__ import annotations

import urllib.error
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from azure.monitor.query import MetricAggregationType, MetricsQueryClient

from coda_core.log_readiness import ReadinessError, check_log_readiness
from coda_core.providers.cost_management import CostManagementProvider
from coda_core.providers.management import BoundCredential, ManagementReader
from coda_core.providers.resource_graph import list_graph_accounts
from coda_core.remediation import guidance
from coda_core.error_contract import normalize_identifier


def _access_denied(exc) -> bool:
    """A denied operation is not itself proof that a role assignment will fix it."""
    if isinstance(exc, ReadinessError) and exc.__cause__ is not None:
        return _access_denied(exc.__cause__)
    status = getattr(exc, "status_code", None)
    if isinstance(exc, urllib.error.HTTPError):
        status = exc.code
    return status == 403


def _error_metadata(exc) -> dict:
    """Expose bounded structured diagnostics, never response prose or token-bearing headers."""
    status = getattr(exc, "status_code", None)
    code = getattr(exc, "code", None)
    if isinstance(exc, urllib.error.HTTPError):
        status = exc.code
        try:
            code = json.loads(exc.read(65536)).get("error", {}).get("code")
        except (ValueError, AttributeError):
            code = None
    return {
        "type": type(exc).__name__,
        "http_status": status if type(status) is int else None,
        "service_code": normalize_identifier(code),
    }


def _failed_check(reader, identity, *, key, label, scope, action, role, exc, optional=False):
    """Suggest a narrow runtime role only when the reported read permission is not already present."""
    denied = _access_denied(exc)
    failure = _error_metadata(exc)
    reported = reader.action(scope, action) if denied else "unknown"
    needs_role = denied and reported != "allowed"
    summary = (
        "The service temporarily rate-limited this read; no permission change is indicated."
        if failure["http_status"] == 429 else
        "Azure denied the read operation." if denied
        else "The read probe failed; this does not establish a missing permission."
    )
    if failure["http_status"]:
        summary += f" HTTP {failure['http_status']}."
    if failure["service_code"]:
        summary += f" Code: {failure['service_code']}."
    reason = (
        "The required read action is already reported. Review deny assignments, PIM, access conditions "
        "or service/billing policy; adding the same role may not help."
        if denied and reported == "allowed" else
        "Wait before rerunning the check. Avoid repeated attempts; optional cost access does not block ordinary diagnosis."
        if failure["http_status"] == 429 else
        "Confirm the current identity and effective access before changing role assignments."
        if denied else "Check authentication, service availability and supported configuration, then retry."
    )
    return {
        "key": key, "label": label, "scope": scope, "optional": optional, "status": "failed",
        "message": summary,
        "failure": failure,
        "remediation": guidance(
            reader, identity, title=label, scope=scope, summary=summary,
            role=role if needs_role else None, reason=reason, admin_needed=denied,
        ),
    }


def _log_fixes(reader, identity, account):
    """Attach setup/access guidance without reclassifying old/empty data as a permission failure."""
    resource = account["resource_id"]
    for source in account.get("sources", []):
        config, data = source["configuration"], source["data"]
        error = config.get("error") or data.get("error")
        source["remediation"] = None
        if error:
            role_scope = None
            workspaces = config.get("workspaces", [])
            failure = data.get("failure", {})
            denied_log_read = failure.get("http_status") == 403 or failure.get("service_code") in {
                "InsufficientAccessError", "AuthorizationFailed",
            }
            if denied_log_read and len(workspaces) == 1:
                try:
                    workspace = reader.request(workspaces[0] + "?api-version=2022-10-01")
                    mode = workspace.get("properties", {}).get("features", {}).get("enableLogAccessUsingOnlyResourcePermissions")
                    if mode is False and reader.action(
                        workspaces[0], "Microsoft.OperationalInsights/workspaces/tables/data/read", data=True
                    ) != "allowed":
                        role_scope = workspaces[0]
                except Exception:  # noqa: BLE001 - unknown workspace policy must not authorize a broad grant
                    role_scope = None
            source["remediation"] = guidance(
                reader, identity, title=f"Verify {source['table']} access",
                scope=role_scope or resource, summary=error["message"],
                role="logs" if role_scope else None,
                reason=(
                    "Workspace-only access requires Log Analytics Data Reader at the identified workspace."
                    if role_scope else
                    "Ask an administrator to verify resource-context access, workspace access mode, table permissions/plan, "
                    "and service availability. Reader at the account can cover resource-context access; "
                    "Log Analytics Data Reader at a workspace is relevant only when workspace/table permissions require it. "
                    f"Known destinations: {', '.join(workspaces) or 'not verified'}. "
                    "No particular role assignment is inferred from this ambiguous failure."
                ),
                admin_needed=True,
            )
        elif config["status"] in {"not_configured", "missing_workspace", "wrong_mode"}:
            source["remediation"] = guidance(
                reader, identity, title=f"Enable {source['category']}",
                scope=resource, category=source["category"],
                summary="The required resource-specific Log Analytics export is not configured.",
                reason="Choose an approved existing workspace when running the script; existing exports are not replaced.",
            )
        elif config["status"] == "unsupported":
            source["remediation"] = guidance(
                reader, identity, title=f"{source['category']} availability", scope=resource,
                summary="This account does not advertise the category.",
                reason="A role assignment cannot enable an unavailable service feature. Use supported sources or confirm availability.",
            )
        elif data["status"] in {"missing", "empty"}:
            source["remediation"] = guidance(
                reader, identity, title=f"{source['table']} data", scope=resource,
                summary="Logging is configured but no records were observed.",
                reason="Allow normal workload activity and ingestion. Extra roles do not create missing history; do not enable duplicate exports.",
            )


def run_prechecks(credential, subscription: str, resource_group: str, account: str | None = None) -> dict:
    """Probe ARM, ARG, metrics, logs and optional cost access; never execute a suggested fix."""
    now = datetime.now(timezone.utc)
    scope = f"/subscriptions/{subscription}/resourceGroups/{resource_group}"
    if account is not None:
        scope += f"/providers/Microsoft.DocumentDB/databaseAccounts/{account}"
    subscription_scope = f"/subscriptions/{subscription}"
    try:
        bound = BoundCredential(credential)
    except Exception:  # noqa: BLE001 - no credentials means no permission conclusions or scripts
        reader = ManagementReader(credential)
        return {
            "subscription": subscription, "resource_group": resource_group, "account": account,
            "checked_at": now.isoformat(), "accounts": [], "accounts_checked": 0,
            "accounts_errored": 0, "identity": None,
            "scope_checks": [{
                "key": "authentication", "label": "Azure sign-in", "scope": scope,
                "status": "failed", "optional": False,
                "message": "CODA could not obtain the credential needed for pre-checks.",
                "remediation": guidance(
                    reader, None, title="Azure sign-in", scope=scope,
                    summary="No Azure access checks were performed.",
                    reason="Use the organization's approved explicit Azure sign-in, then retry. No role assignment has been inferred.",
                ),
            }],
            "note": "Authentication could not be established. Other pre-checks were not run; no changes were made.",
        }
    reader = ManagementReader(bound)
    identity = bound.identity
    checks = []
    try:
        logs = check_log_readiness(bound, subscription, resource_group, account)
        checks.append({
            "key": "arm", "label": "Azure Resource Manager", "scope": scope, "optional": False,
            "status": "passed", "message": "Selected account/discovery metadata is readable.",
        })
    except ReadinessError as exc:
        logs = {
            "subscription": subscription, "resource_group": resource_group, "account": account,
            "accounts": [], "accounts_checked": 0, "accounts_errored": 0, "checked_at": now.isoformat(),
        }
        checks.append(_failed_check(
            reader, identity, key="arm", label="Azure Resource Manager", scope=scope,
            action="Microsoft.DocumentDB/databaseAccounts/read", role="reader", exc=exc,
        ))
    try:
        graph_accounts = list_graph_accounts(
            bound, subscription, resource_group=resource_group, account=account,
        )
        expected = {row["account"].casefold() for row in logs["accounts"]}
        observed = {name.casefold() for _, name in graph_accounts}
        complete = expected <= observed
        checks.append({
            "key": "arg", "label": "Azure Resource Graph", "scope": scope, "optional": True,
            "status": "passed" if complete else "warning",
            "message": (
                f"ARG query succeeded with the same identity; {len(observed)} matching account(s) visible."
                if complete else "ARG query succeeded but some ARM accounts were not visible. Indexing delay or scope visibility may be involved."
            ),
            "remediation": None if complete else guidance(
                reader, identity, title="ARG visibility", scope=scope,
                summary="ARM and ARG visibility differ.",
                reason="Allow Resource Graph indexing and verify scope/identity. An empty or incomplete result is not proof of a missing role.",
            ),
        })
    except Exception as exc:  # noqa: BLE001 - preserve independent probe failure without disabling diagnosis
        checks.append(_failed_check(
            reader, identity, key="arg", label="Azure Resource Graph", scope=scope,
            action="Microsoft.ResourceGraph/resources/read", role="reader", exc=exc, optional=True,
        ))
    try:
        cost = CostManagementProvider(bound, subscription, timeout_seconds=20, max_retries=0)
        result = cost.cosmos_throughput_cost((now - timedelta(days=30)).date(), now.date())
        checks.append({
            "key": "cost", "label": "Cost Management", "scope": subscription_scope, "optional": True,
            "status": "passed",
            "message": (
                "Subscription cost query succeeded; matching amortized throughput data is available."
                if result.has_usage else "Subscription cost query succeeded; no matching throughput billing data was returned. This is not a permission failure."
            ),
        })
    except Exception as exc:  # noqa: BLE001 - cost is optional and billing policies differ from resource RBAC
        checks.append(_failed_check(
            reader, identity, key="cost", label="Cost Management", scope=subscription_scope,
            action="Microsoft.CostManagement/query/read", role="cost", exc=exc, optional=True,
        ))

    def inspect(row):
        """Bound one metrics read and attach issue guidance to the existing per-account log result."""
        resource = row["resource_id"]
        try:
            with MetricsQueryClient(bound, connection_timeout=5, read_timeout=20, retry_total=0) as metrics:
                response = metrics.query_resource(
                    resource, metric_names=["TotalRequests"], aggregations=[MetricAggregationType.COUNT],
                    timespan=(now - timedelta(hours=1), now), granularity=timedelta(minutes=5),
                )
                if any(getattr(metric, "error_code", None) not in (None, "", "Success") for metric in response.metrics):
                    raise ValueError("Metrics service returned an unsuccessful metric result.")
                points = sum(
                    datum.count is not None for metric in response.metrics
                    for series in metric.timeseries for datum in series.data
                )
            row["access_checks"] = [{
                "key": "metrics", "label": "Azure Monitor metrics", "scope": resource, "optional": False,
                "status": "passed", "message": (
                    f"Metric read succeeded; {points} data point(s) returned."
                    if points else "Metric read succeeded with no current data points; this is not a permission failure."
                ),
            }]
        except Exception as exc:  # noqa: BLE001 - one account/service must not hide other check results
            row["access_checks"] = [_failed_check(
                reader, identity, key="metrics", label="Azure Monitor metrics", scope=resource,
                action="Microsoft.Insights/metrics/read", role="reader", exc=exc,
            )]
            if row.get("status") != "error":
                row["status"] = "unverified"
        _log_fixes(reader, identity, row)
        return row

    if logs["accounts"]:
        with ThreadPoolExecutor(max_workers=min(4, len(logs["accounts"]))) as pool:
            logs["accounts"] = list(pool.map(inspect, logs["accounts"]))
        logs["accounts_errored"] = sum(row.get("status") != "checked" for row in logs["accounts"])
    if bound.changed or bound.unverifiable:
        raise ReadinessError(guidance_identity_error())
    return {
        **logs, "scope_checks": checks, "identity": identity,
        "note": (
            "Read-only pre-checks for ARM, ARG, Azure Monitor metrics, Log Analytics and optional subscription Cost Management. "
            "They do not prove health, complete history or all descendant permissions. Fixes are copy-only; CODA never executes them. "
            "Cost/ARG warnings do not block ordinary diagnosis."
        ),
    }


def guidance_identity_error():
    """Suppress all remediation when a credential changes subject during a run."""
    from coda_core.error_contract import StableError

    return StableError(
        "prechecks.identity_changed", "authentication", False,
        "A consistent requester identity could not be verified across pre-checks.",
        "Sign in consistently and run pre-checks again before requesting any permission changes.",
        "Do not use stale requester identity or permission results.",
    )

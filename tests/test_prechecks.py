"""Offline access/remediation contracts; scripts are never executed against Azure by these tests."""

import base64
import json
from contextlib import nullcontext
from types import SimpleNamespace as NS

import pytest
from azure.core.credentials import AccessToken

from coda_core import prechecks, remediation
from coda_core.providers.management import BoundCredential, ManagementReadError, ManagementReader
from coda_core.providers import resource_graph

pytestmark = pytest.mark.public
SUB = "11111111-2222-3333-4444-555555555555"
TENANT = "22222222-2222-3333-4444-555555555555"
PRINCIPAL = "33333333-2222-3333-4444-555555555555"
SCOPE = f"/subscriptions/{SUB}/resourceGroups/customer-rg"
IDENTITY = {"object_id": PRINCIPAL, "tenant_id": TENANT}


def _token(oid=PRINCIPAL):
    payload = base64.urlsafe_b64encode(json.dumps({"oid": oid, "tid": TENANT}).encode()).decode().rstrip("=")
    return AccessToken(f"header.{payload}.signature", 9999999999)


class Credential:
    def get_token(self, *_args, **_kwargs):
        return _token()


class Permissions:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def action(self, scope, action, **kwargs):
        self.calls.append((scope, action, kwargs))
        return self.result


def test_role_script_targets_requester_not_executing_administrator():
    result = remediation.guidance(
        Permissions("allowed"), IDENTITY, title="ARM access", scope=SCOPE,
        summary="Read denied", role="reader",
    )
    script = result["script"]
    assert f"$PrincipalObjectId = '{PRINCIPAL}'" in script
    assert f"$Scope = '{SCOPE}'" in script
    assert remediation.ROLES["reader"][1] in script
    assert "--assignee-object-id" in script
    assert "signed-in-user" not in script
    assert "param([switch]$Apply)" in script
    assert script.index("if (-not $Apply)") < script.index("'assignment','create'")
    assert "account','set" not in script
    assert result["required_role"] == "Reader"


@pytest.mark.parametrize("reported", ["absent", "unknown"])
def test_unverified_administration_gets_exact_admin_request_not_script(reported):
    result = remediation.guidance(
        Permissions(reported), IDENTITY, title="Cost access",
        scope=f"/subscriptions/{SUB}", summary="Cost access denied", role="cost",
    )
    assert result["script"] is None
    assert result["administrative_access"] == reported
    assert "Cost Management Reader" in result["admin_request"]
    assert PRINCIPAL in result["admin_request"]
    assert f"/subscriptions/{SUB}" in result["admin_request"]
    assert remediation.ROLE_WRITE in result["admin_request"]
    assert "administrator" in result["message"]


def test_unknown_requester_never_gets_permission_script():
    result = remediation.guidance(
        Permissions("allowed"), None, title="Access", scope=SCOPE, summary="Denied", role="reader",
    )
    assert result["script"] is None
    assert "confirm the requester object ID" in result["admin_request"]


def test_logging_script_requires_workspace_and_preserves_existing_exports():
    result = remediation.guidance(
        Permissions("allowed"), IDENTITY, title="Logs", scope=SCOPE + "/providers/Microsoft.DocumentDB/databaseAccounts/account-one",
        summary="Missing export", category="DataPlaneRequests5M",
    )
    script = result["script"]
    assert "[Parameter(Mandatory)][string]$WorkspaceResourceId" in script
    assert "resource-specific mode" in script
    assert "No change made" in script
    assert "diagnosticSettingsCategories" in script
    assert "categoryGroups" in script
    assert "logAnalyticsDestinationType = 'Dedicated'" in script
    assert "[Guid]::NewGuid()" in script
    assert "capacity is exhausted" in script
    assert script.index("if (-not $Apply)") < script.index("'--method','put'")
    assert "'--method','delete'" not in script
    assert "'role','assignment','create'" not in script
    assert "does not choose or create a workspace" in script


def test_unavailable_future_category_cannot_be_generated():
    with pytest.raises(ValueError):
        remediation.guidance(
            Permissions("allowed"), IDENTITY, title="Logs", scope=SCOPE,
            summary="Unknown", category="QueryRuntimeStatistics5M",
        )


def test_management_client_rejects_foreign_endpoints_and_non_read_posts():
    reader = ManagementReader(Credential())
    with pytest.raises(ValueError):
        reader.request("https://example.invalid/permissions")
    with pytest.raises(ValueError):
        reader.request(SCOPE + "/providers/Microsoft.Authorization/roleAssignments", {})


def test_permissions_union_honors_not_actions_per_grant_and_unknown_conditions():
    reader = ManagementReader(Credential())
    reader._permissions[SCOPE] = {"status": "observed", "entries": [
        {"actions": ["*"], "notActions": ["Microsoft.Authorization/*/write"]},
        {"actions": ["Microsoft.Authorization/roleAssignments/write"], "notActions": []},
    ]}
    assert reader.action(SCOPE, remediation.ROLE_WRITE) == "allowed"
    reader._permissions[SCOPE]["entries"] = [
        {"actions": ["*"], "notActions": [], "condition": "restricted"},
    ]
    assert reader.action(SCOPE, remediation.ROLE_WRITE) == "unknown"
    reader._permissions[SCOPE]["entries"] = [{"actions": ["*/read"], "notActions": []}]
    assert reader.action(SCOPE, remediation.ROLE_WRITE) == "absent"


def test_credential_identity_drift_is_detected():
    class ChangingCredential:
        def __init__(self):
            self.count = 0

        def get_token(self, *_args, **_kwargs):
            self.count += 1
            return _token(PRINCIPAL if self.count == 1 else SUB)

    bound = BoundCredential(ChangingCredential())
    with pytest.raises(ManagementReadError):
        bound.get_token("https://management.azure.com/.default")
    assert bound.changed


def test_arg_uses_injected_identity_and_scoped_complete_pages(monkeypatch):
    calls = []

    class Reader:
        def __init__(self, credential):
            assert credential is token

        def request(self, path, body):
            calls.append(body)
            return {"data": [{"id": SCOPE + "/providers/Microsoft.DocumentDB/databaseAccounts/account-one",
                              "resourceGroup": "customer-rg", "name": "account-one"}],
                    "resultTruncated": "false"}

    token = object()
    monkeypatch.setattr(resource_graph, "ManagementReader", Reader)
    assert resource_graph.list_graph_accounts(token, SUB, resource_group="customer-rg") == [
        ("customer-rg", "account-one")
    ]
    assert calls[0]["subscriptions"] == [SUB]
    assert "resourceGroup =~ 'customer-rg'" in calls[0]["query"]


def test_arg_refuses_incomplete_inventory(monkeypatch):
    class Reader:
        def __init__(self, _credential):
            pass

        def request(self, *_args):
            return {"data": [], "resultTruncated": "true"}

    monkeypatch.setattr(resource_graph, "ManagementReader", Reader)
    with pytest.raises(ValueError, match="truncated"):
        resource_graph.list_graph_accounts(object(), SUB)


def test_all_five_probes_preserve_empty_data_and_cost_as_optional(monkeypatch):
    resource = SCOPE + "/providers/Microsoft.DocumentDB/databaseAccounts/account-one"
    monkeypatch.setattr(prechecks, "check_log_readiness", lambda *_args: {
        "accounts_checked": 1, "accounts_errored": 0,
        "accounts": [{"account": "account-one", "resource_id": resource, "sources": []}],
    })
    monkeypatch.setattr(prechecks, "list_graph_accounts", lambda *_args, **_kw: [("customer-rg", "account-one")])
    monkeypatch.setattr(prechecks, "CostManagementProvider", lambda *_args, **kwargs: NS(
        cosmos_throughput_cost=lambda *_a: NS(has_usage=False)
    ))
    monkeypatch.setattr(prechecks, "MetricsQueryClient", lambda *_a, **_kw: nullcontext(NS(
        query_resource=lambda *_a, **_kw: NS(metrics=[])
    )))
    result = prechecks.run_prechecks(Credential(), SUB, "customer-rg", "account-one")
    assert {check["key"] for check in result["scope_checks"]} == {"arm", "arg", "cost"}
    cost = next(check for check in result["scope_checks"] if check["key"] == "cost")
    assert cost["optional"] is True and cost["status"] == "passed"
    assert "not a permission failure" in cost["message"]
    assert result["accounts"][0]["access_checks"][0]["status"] == "passed"


def test_reported_read_permission_does_not_generate_duplicate_role_for_policy_denial():
    class Denied(RuntimeError):
        status_code = 403

    reader = Permissions("allowed")
    result = prechecks._failed_check(
        reader, IDENTITY, key="cost", label="Cost Management",
        scope=f"/subscriptions/{SUB}", action="Microsoft.CostManagement/query/read",
        role="cost", exc=Denied("private-error-text"), optional=True,
    )
    assert result["remediation"]["script"] is None
    assert result["remediation"]["required_role"] is None
    assert "policy" in result["remediation"]["reason"]
    assert "private-error-text" not in json.dumps(result)


def test_throttling_never_suggests_a_permission_grant():
    class Limited(RuntimeError):
        status_code = 429

    reader = Permissions("allowed")
    result = prechecks._failed_check(
        reader, IDENTITY, key="cost", label="Cost Management", scope=f"/subscriptions/{SUB}",
        action="Microsoft.CostManagement/query/read", role="cost", exc=Limited(), optional=True,
    )
    assert "rate-limited" in result["message"]
    assert result["remediation"]["script"] is None
    assert result["remediation"]["required_role"] is None
    assert result["remediation"]["administrator_needed"] is False
    assert reader.calls == []


def test_authentication_failure_never_suggests_a_role_assignment():
    class Unauthenticated(RuntimeError):
        status_code = 401

    reader = Permissions("allowed")
    result = prechecks._failed_check(
        reader, IDENTITY, key="metrics", label="Metrics", scope=SCOPE,
        action="Microsoft.Insights/metrics/read", role="reader", exc=Unauthenticated(),
    )
    assert result["remediation"]["script"] is None
    assert result["remediation"]["required_role"] is None
    assert reader.calls == []

"""Offline contracts for read-only readiness; live evidence is retained separately."""

from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import pytest
from azure.monitor.query import LogsQueryResult, LogsTable

from coda_core import log_readiness as readiness
from coda_core.pipeline.capabilities import CAPABILITIES
from coda_core.providers.log_analytics import LogAnalyticsQueryError

pytestmark = pytest.mark.public
SUB = "11111111-2222-3333-4444-555555555555"
GROUP = "customer-rg"
NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
TABLES = ("CDBDataPlaneRequests5M", "CDBDataPlaneRequests", "CDBQueryRuntimeStatistics")


def _account(name="account-one", group=GROUP):
    return NS(
        name=name, kind="GlobalDocumentDB", capabilities=[],
        id=f"/subscriptions/{SUB}/resourceGroups/{group}/providers/Microsoft.DocumentDB/databaseAccounts/{name}",
    )


def _setting(category=None, group=None, *, enabled=True, mode="Dedicated", workspace="workspace-one"):
    return NS(
        workspace_id=f"/subscriptions/{SUB}/resourceGroups/logs/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
        if workspace else None,
        log_analytics_destination_type=mode,
        logs=[NS(category=category, category_group=group, enabled=enabled)],
    )


def _install(monkeypatch, *, accounts=None, settings=None, outcomes=None, config_error=None):
    """Install read-only SDK facades with operation recording, not fixture-mutation shims."""
    accounts = accounts if accounts is not None else [_account()]
    settings = settings if settings is not None else [_setting(group="allLogs")]
    outcomes = outcomes or {}
    calls = []
    categories = [
        NS(name=category, category_type="Logs", category_groups=["allLogs"])
        for category in ("DataPlaneRequests5M", "DataPlaneRequests", "QueryRuntimeStatistics")
    ]

    def get(group, name, **kwargs):
        calls.append(("get", group, name, kwargs))
        return next(item for item in accounts if item.name == name)

    def list_group(group, **kwargs):
        calls.append(("list_group", group, kwargs))
        return accounts

    def list_categories(resource, **kwargs):
        calls.append(("categories", resource, kwargs))
        return categories

    def list_settings(resource, **kwargs):
        calls.append(("settings", resource, kwargs))
        if config_error:
            raise config_error
        return settings

    class Logs:
        def query_resource(self, resource, query, *, timespan, server_timeout):
            table = query.split("|")[0].strip()
            calls.append(("query", resource, table, timespan, server_timeout))
            outcome = outcomes.get((resource.rsplit("/", 1)[-1], table), outcomes.get(table))
            if isinstance(outcome, Exception):
                raise outcome
            count, latest = outcome if outcome is not None else (5, NOW - timedelta(hours=1))
            return LogsQueryResult(tables=[
                LogsTable(
                    name="PrimaryResult", columns=["n", "last_seen"],
                    columns_types=["long", "datetime"], rows=[[count, latest]],
                )
            ])

    monkeypatch.setattr(readiness, "datetime", NS(now=lambda _tz: NOW))
    monkeypatch.setattr(
        readiness, "CosmosDBManagementClient",
        lambda *_args: nullcontext(NS(database_accounts=NS(get=get, list_by_resource_group=list_group))),
    )
    monkeypatch.setattr(
        readiness, "MonitorManagementClient",
        lambda *_args: nullcontext(NS(
            diagnostic_settings_category=NS(list=list_categories),
            diagnostic_settings=NS(list=list_settings),
        )),
    )
    monkeypatch.setattr(readiness, "LogsQueryClient", lambda *_args, **_kwargs: nullcontext(Logs()))
    return calls


def _missing(table):
    return LogAnalyticsQueryError(status="PartialError", message=f"'{table}' could not be resolved")


def test_single_account_checks_configuration_and_data_without_group_enumeration(monkeypatch):
    calls = _install(monkeypatch)
    result = readiness.check_log_readiness(object(), SUB, GROUP, "account-one")
    account = result["accounts"][0]
    assert not any(call[0] == "list_group" for call in calls)
    assert result["accounts_checked"] == 1 and result["accounts_errored"] == 0
    assert all(source["configuration"]["status"] == "configured" for source in account["sources"])
    assert all(source["data"]["status"] == "recent" for source in account["sources"])
    assert all(detector["status"] == "available" for detector in account["detectors"])
    assert account["selected_request_source"] == "CDBDataPlaneRequests5M"
    assert [row["id"] for row in account["detectors"]] == ["DX-002", "DX-003", "DX-007", "DX-010", "DX-016"]
    assert account["detectors"][-1]["optional"] is True
    assert all(call[-1]["retry_total"] == 0 for call in calls if call[0] in {"get", "settings", "categories"})
    assert all(call[-1] == 15 for call in calls if call[0] == "query")


def test_configured_but_empty_is_waiting_for_data_not_disabled(monkeypatch):
    _install(monkeypatch, outcomes={table: (0, None) for table in (*TABLES, "AzureDiagnostics")})
    account = readiness.check_log_readiness(object(), SUB, GROUP, "account-one")["accounts"][0]
    assert all(source["configuration"]["status"] == "configured" for source in account["sources"])
    assert all(source["data"]["status"] == "empty" for source in account["sources"])
    assert all(detector["status"] == "needs_data" for detector in account["detectors"])


def test_old_records_are_not_recent_or_proof_of_current_export(monkeypatch):
    _install(monkeypatch, settings=[], outcomes={table: (10, NOW - timedelta(days=2)) for table in TABLES})
    account = readiness.check_log_readiness(object(), SUB, GROUP, "account-one")["accounts"][0]
    assert all(source["configuration"]["status"] == "not_configured" for source in account["sources"])
    assert all(source["data"]["status"] == "older_data" for source in account["sources"])
    assert all(detector["status"] == "needs_setup" for detector in account["detectors"])


@pytest.mark.parametrize(("setting", "expected"), [
    (_setting(group="allLogs", mode=None), "wrong_mode"),
    (_setting(group="allLogs", workspace=None), "missing_workspace"),
    (_setting(group="allLogs", enabled=False), "not_configured"),
])
def test_wrong_mode_destination_and_disabled_groups_remain_distinct(monkeypatch, setting, expected):
    _install(monkeypatch, settings=[setting])
    account = readiness.check_log_readiness(object(), SUB, GROUP, "account-one")["accounts"][0]
    assert all(source["configuration"]["status"] == expected for source in account["sources"])


def test_existing_raw_fallback_can_supply_aggregate_detectors(monkeypatch):
    _install(
        monkeypatch, settings=[_setting(category="DataPlaneRequests")],
        outcomes={"CDBDataPlaneRequests5M": _missing("CDBDataPlaneRequests5M")},
    )
    account = readiness.check_log_readiness(object(), SUB, GROUP, "account-one")["accounts"][0]
    assert account["selected_request_source"] == "CDBDataPlaneRequests"
    states = {row["id"]: row["status"] for row in account["detectors"]}
    assert states["DX-003"] == states["DX-010"] == states["DX-016"] == "available"
    assert states["DX-002"] == states["DX-007"] == "needs_setup"


def test_group_keeps_access_failure_visible_without_leaking_prose_or_blocking_other_accounts(monkeypatch):
    class Denied(RuntimeError):
        status_code = 403

    _install(
        monkeypatch, accounts=[_account("account-two"), _account("account-one")],
        outcomes={("account-two", "CDBDataPlaneRequests5M"): Denied("sensitive-token-do-not-return")},
    )
    result = readiness.check_log_readiness(object(), SUB, GROUP)
    assert result["accounts_checked"] == 2 and result["accounts_errored"] == 1
    first, second = result["accounts"]
    assert first["account"] == "account-one" and first["status"] == "checked"
    assert second["status"] == "unverified"
    assert second["sources"][0]["data"]["status"] == "error"
    assert second["sources"][0]["help_url"] == readiness.LOG_ACCESS_URL
    assert "sensitive-token-do-not-return" not in json.dumps(result)
    assert next(row for row in second["detectors"] if row["id"] == "DX-010")["status"] == "unverified"


def test_configuration_failure_does_not_turn_readable_logs_into_missing_tables(monkeypatch):
    _install(monkeypatch, config_error=RuntimeError("private failure detail"))
    account = readiness.check_log_readiness(object(), SUB, GROUP, "account-one")["accounts"][0]
    assert account["status"] == "unverified"
    assert all(row["configuration"]["status"] == "unknown" for row in account["sources"])
    assert all(row["data"]["status"] == "recent" for row in account["sources"])
    assert "private failure detail" not in json.dumps(account)


def test_empty_group_is_explicit_and_never_expands_to_subscription(monkeypatch):
    calls = _install(monkeypatch, accounts=[])
    result = readiness.check_log_readiness(object(), SUB, GROUP)
    assert result["accounts"] == [] and result["accounts_checked"] == 0
    assert [call[0] for call in calls] == ["list_group"]
    assert calls[0][1] == GROUP


def test_foreign_resource_identity_is_rejected_before_log_queries(monkeypatch):
    calls = _install(monkeypatch, accounts=[_account(group="another-group")])
    with pytest.raises(readiness.ReadinessError):
        readiness.check_log_readiness(object(), SUB, GROUP)
    assert not any(call[0] == "query" for call in calls)


def test_malformed_enabled_state_is_unknown_not_configured(monkeypatch):
    _install(monkeypatch, settings=[_setting(group="allLogs", enabled="false")])
    account = readiness.check_log_readiness(object(), SUB, GROUP, "account-one")["accounts"][0]
    assert all(row["configuration"]["status"] == "unknown" for row in account["sources"])


def test_source_metadata_uses_known_capabilities_and_keeps_optional_enrichment_separate():
    requirements = readiness.log_detector_requirements()
    for row in requirements:
        assert set(row["required"] + row["optional"]) <= CAPABILITIES.keys()
    optional = next(row for row in requirements if row["id"] == "DX-016")
    assert optional["required"] == [] and optional["optional"]


@pytest.mark.parametrize("outcome", [(5, None), (0, NOW), (True, NOW)])
def test_malformed_probe_is_unverified_not_missing_configuration(monkeypatch, outcome):
    _install(monkeypatch, outcomes={"CDBDataPlaneRequests5M": outcome})
    account = readiness.check_log_readiness(object(), SUB, GROUP, "account-one")["accounts"][0]
    source = account["sources"][0]
    assert source["configuration"]["status"] == "configured"
    assert source["data"]["status"] == "error"
    assert source["data"]["error"]["retryable"] is False
    assert next(row for row in account["detectors"] if row["id"] == "DX-010")["status"] == "unverified"

"""Read-only log configuration and data checks, separate from diagnosis and account health."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

from azure.core.credentials import TokenCredential
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.monitor.query import LogsQueryClient

from coda_core.error_contract import StableError, normalize_identifier
from coda_core.pipeline.capabilities import (
    CAP_LA_REQUEST_AGGREGATES,
    CAPABILITIES,
    CapabilitySet,
    log_source_tables,
    resolve_capabilities,
)
from coda_core.pipeline.registry import (
    ACCOUNT_REGISTRY,
    DATABASE_REGISTRY,
    REGISTRY,
    SERVERLESS_REGISTRY,
)
from coda_core.providers.arm import account_config_from_arm
from coda_core.providers.log_analytics import DataPlaneSource, _rows_from_response
from coda_core.scan import NOSQL_KIND

LOG_SETUP_URL = (
    "https://learn.microsoft.com/en-us/azure/cosmos-db/monitor-resource-logs"
    "?tabs=azure-portal#create-diagnostic-settings"
)
AGGREGATE_SETUP_URL = "https://learn.microsoft.com/en-us/azure/cosmos-db/monitor-aggregated-logs"
LOG_ACCESS_URL = "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access"
_READ_OPTIONS = {"connection_timeout": 5, "read_timeout": 20, "retry_total": 0}
_LOGGER = logging.getLogger(__name__)


class ReadinessError(RuntimeError):
    """Carry safe discovery failures without exposing Azure exception text through the web API."""

    def __init__(self, failure: StableError) -> None:
        super().__init__(failure.message)
        self.failure = failure


class _BoundedLogReader:
    """Adapt an owned, bounded SDK client to the existing capability-probe interface."""

    def __init__(self, client: LogsQueryClient) -> None:
        self.client = client

    def query_resource(self, resource_id, query, timespan):
        """Use the shared strict response conversion; partial responses remain errors."""
        return _rows_from_response(self.client.query_resource(
            resource_id, query, timespan=timespan, server_timeout=15,
        ))


def _failure(phase: str, *, http_status=None, error_type=None, service_code=None) -> StableError:
    """Describe observed read failures safely without inferring a particular policy or role."""
    denied = http_status in (401, 403) or str(service_code).casefold() in {
        "authorizationfailed", "insufficientaccesserror", "forbidden",
    } or error_type in {"ClientAuthenticationError", "CredentialUnavailableError"}
    code = "readiness.access_denied" if denied else "readiness.unverified"
    transient = (
        type(http_status) is int and (http_status == 429 or 500 <= http_status <= 599)
    ) or error_type == "TimeoutError"
    _LOGGER.warning("Log readiness %s failed: %s (%s)", phase, code, error_type)
    return StableError(
        code=code, category="log_readiness", retryable=transient and not denied,
        message=(
            f"Azure denied access while checking {phase}." if denied
            else f"Could not verify {phase}."
        ),
        user_action=(
            "Check the selected scope, local Azure sign-in, and resource/log read access."
            if denied else "Check Azure availability and read access, then retry the check."
        ),
        admin_action="Review read permissions, table access/plan and applicable access policies.",
    )


def _exception_failure(phase: str, exc: Exception) -> StableError:
    """Extract only typed exception metadata, never remote error prose."""
    return _failure(
        phase, http_status=getattr(exc, "status_code", None), error_type=type(exc).__name__,
        service_code=getattr(getattr(exc, "error", None), "code", None),
    )


def log_detector_requirements() -> list[dict[str, Any]]:
    """Derive the five log-using paths from the same registry used by diagnosis."""
    entries: dict[str, dict[str, Any]] = {}
    for adapter in (*REGISTRY, *ACCOUNT_REGISTRY, *DATABASE_REGISTRY, *SERVERLESS_REGISTRY):
        required = {key for key in adapter.requires if CAPABILITIES[key].is_log_analytics}
        optional = {
            key for key in getattr(adapter, "optional_requires", ())
            if CAPABILITIES[key].is_log_analytics
        }
        if not required and not optional:
            continue
        entry = entries.setdefault(adapter.detection_id, {
            "id": adapter.detection_id, "name": adapter.title,
            "required": set(), "optional": set(),
        })
        entry["required"].update(required)
        entry["optional"].update(optional)
    return [
        {**entry, "required": sorted(entry["required"]), "optional": sorted(entry["optional"])}
        for _, entry in sorted(entries.items())
    ]


def _configuration(monitor, resource_id: str, descriptors: dict) -> dict[str, dict]:
    """Read account-specific exports, including category groups and destination table mode."""
    categories = {}
    for item in monitor.diagnostic_settings_category.list(resource_id, **_READ_OPTIONS):
        if item.category_type != "Logs":
            continue
        if not isinstance(item.name, str) or not item.name:
            raise ValueError("Diagnostic category has no name.")
        categories[item.name.casefold()] = frozenset(
            group.casefold() for group in item.category_groups or ()
        )
    settings = list(monitor.diagnostic_settings.list(resource_id, **_READ_OPTIONS))

    def matches(log, category: str) -> bool:
        """Handle named categories and groups without treating malformed booleans as enabled."""
        if type(log.enabled) is not bool:
            raise ValueError("Diagnostic category enabled state is invalid.")
        if not log.enabled:
            return False
        if bool(log.category) == bool(log.category_group):
            raise ValueError("Diagnostic log must name exactly one category or group.")
        if log.category:
            return log.category.casefold() == category
        group = log.category_group.casefold()
        return (
            group == "alllogs" and category in categories
            or group in categories.get(category, ())
        )

    results = {}
    for table, descriptor in descriptors.items():
        category = descriptor.category.casefold()
        dedicated, legacy = set(), set()
        other_destination = False
        for setting in settings:
            enabled = any(matches(log, category) for log in setting.logs or ())
            if not enabled:
                continue
            if not setting.workspace_id:
                other_destination = True
            elif not isinstance(setting.workspace_id, str):
                raise ValueError("Diagnostic workspace identity is invalid.")
            elif (setting.log_analytics_destination_type or "").casefold() == "dedicated":
                dedicated.add(setting.workspace_id)
            elif (setting.log_analytics_destination_type or "").casefold() in {"", "azurediagnostics"}:
                legacy.add(setting.workspace_id)
            else:
                raise ValueError("Unknown Log Analytics destination table mode.")
        state = (
            "configured" if dedicated else "wrong_mode" if legacy
            else "missing_workspace" if other_destination
            else "not_configured" if category in categories else "unsupported"
        )
        results[table] = {"status": state, "workspaces": sorted(dedicated | legacy)}
    return results


def _dependency_state(key: str, sources: dict, caps: CapabilitySet) -> tuple[str, list[str]]:
    """Explain logging prerequisites without promising detector applicability or sample sufficiency."""
    accepted = log_source_tables(key)
    if caps.probe_error_for(frozenset({key})):
        return "unverified", list(accepted)
    if not caps.has(key):
        configs = [sources[table]["configuration"]["status"] for table in accepted]
        state = (
            "needs_data" if "configured" in configs
            else "unverified" if "unknown" in configs else "needs_setup"
        )
        return state, list(accepted)
    table = (
        caps.dataplane_source.value
        if key == CAP_LA_REQUEST_AGGREGATES and caps.dataplane_source is not None
        else accepted[0]
    )
    source = sources[table]
    config = source["configuration"]["status"]
    state = (
        "unverified" if config == "unknown" else "needs_setup" if config != "configured"
        else "available" if source["data"]["status"] == "recent" else "needs_data"
    )
    return state, [table]


def _check_account(credential, subscription, group, account, resource_id, now) -> dict:
    """Inspect one account with independent configuration/data outcomes and owned SDK clients."""
    descriptors = {
        descriptor.la_table: descriptor
        for descriptor in CAPABILITIES.values() if descriptor.is_log_analytics
    }
    try:
        with MonitorManagementClient(credential, subscription) as monitor:
            configuration = _configuration(monitor, resource_id, descriptors)
    except Exception as exc:  # noqa: BLE001 - preserve the error while still testing log readability
        failure = _exception_failure("diagnostic settings", exc).as_dict()
        configuration = {
            table: {"status": "unknown", "workspaces": [], "error": failure}
            for table in descriptors
        }
    span = (now - timedelta(days=30), now)
    with LogsQueryClient(credential, **_READ_OPTIONS) as client:
        caps = resolve_capabilities(
            la=_BoundedLogReader(client), account_resource_id=resource_id, span=span,
            include_latest=True,
        )
    observations = {item.table: item for item in caps.table_observations}
    sources = {}
    for table, descriptor in descriptors.items():
        observation = observations[table]
        latest = observation.last_seen
        data = {
            "status": (
                "recent" if latest is not None and latest >= now - timedelta(days=1)
                else "older_data" if observation.state == "present" else observation.state
            ),
            "log_rows_in_probe": observation.row_count,
            "last_seen": latest.isoformat() if latest is not None else None,
        }
        if observation.error is not None:
            data["failure"] = {
                "http_status": observation.http_status if type(observation.http_status) is int else None,
                "error_type": observation.error_type,
                "service_code": normalize_identifier(observation.service_code),
            }
            data["error"] = _failure(
                "log data", http_status=observation.http_status,
                error_type=observation.error_type, service_code=observation.service_code,
            ).as_dict()
        denied = any(
            item.get("error", {}).get("code") == "readiness.access_denied"
            for item in (configuration[table], data)
        )
        sources[table] = {
            "table": table, "category": descriptor.category,
            "configuration": configuration[table], "data": data,
            "help_url": (
                LOG_ACCESS_URL if denied else AGGREGATE_SETUP_URL
                if table == DataPlaneSource.FIVE_MINUTE.value else LOG_SETUP_URL
            ),
        }
    detectors = []
    priority = {"available": 0, "needs_data": 1, "needs_setup": 2, "unverified": 3}
    for entry in log_detector_requirements():
        states = [_dependency_state(key, sources, caps) for key in entry["required"] or entry["optional"]]
        detectors.append({
            "id": entry["id"], "name": entry["name"], "optional": not bool(entry["required"]),
            "status": max((state for state, _ in states), key=priority.__getitem__),
            "tables": sorted({table for _, tables in states for table in tables}),
        })
    workspaces = {workspace for source in sources.values() for workspace in source["configuration"]["workspaces"]}
    unverified = any(
        "error" in source["configuration"] or "error" in source["data"]
        for source in sources.values()
    )
    return {
        "account": account, "resource_group": group, "resource_id": resource_id,
        "status": "unverified" if unverified else "checked", "sources": sorted(
            sources.values(), key=lambda source: (source["table"] != DataPlaneSource.FIVE_MINUTE.value, source["table"]),
        ),
        "detectors": detectors, "multiple_destinations": len(workspaces) > 1,
        "selected_request_source": caps.dataplane_source.value if caps.dataplane_source else None,
    }


def check_log_readiness(
    credential: TokenCredential, subscription: str, resource_group: str, account: str | None = None,
) -> dict:
    """Check only the selected NoSQL account/group; never run detectors or mutate Azure."""
    now = datetime.now(timezone.utc)
    try:
        with CosmosDBManagementClient(credential, subscription) as cosmos:
            models = (
                [cosmos.database_accounts.get(resource_group, account, **_READ_OPTIONS)]
                if account is not None else
                list(cosmos.database_accounts.list_by_resource_group(resource_group, **_READ_OPTIONS))
            )
    except Exception as exc:  # noqa: BLE001 - scope discovery cannot be represented as an empty group
        raise ReadinessError(_exception_failure("account discovery", exc)) from exc
    targets = []
    for model in models:
        if any(not isinstance(getattr(model, field, None), str) or not getattr(model, field)
               for field in ("name", "id", "kind")):
            raise ReadinessError(_failure("account scope", error_type="InvalidResourceIdentity"))
        if model.kind != NOSQL_KIND or account_config_from_arm(model).is_mongo:
            if account is not None:
                raise ReadinessError(StableError(
                    "readiness.unsupported_api", "request_scope", False,
                    "Log readiness currently supports Cosmos DB for NoSQL accounts only.",
                    "Select a supported NoSQL account.", "No resource changes are required.",
                ))
            continue
        expected = (
            f"/subscriptions/{subscription}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.DocumentDB/databaseAccounts/{model.name}"
        )
        if not model.name or not model.id or model.id.casefold() != expected.casefold():
            raise ReadinessError(_failure("account scope", error_type="InvalidResourceIdentity"))
        if account is not None and model.name.casefold() != account.casefold():
            raise ReadinessError(_failure("account scope", error_type="InvalidResourceIdentity"))
        targets.append((model.name, model.id))

    def inspect(target):
        """Keep one failed account visible without aborting the other accounts in a group."""
        name, resource_id = target
        try:
            return _check_account(credential, subscription, resource_group, name, resource_id, now)
        except Exception as exc:  # noqa: BLE001 - explicit per-account isolation, never a clean result
            return {
                "account": name, "resource_group": resource_group, "resource_id": resource_id,
                "status": "error", "sources": [], "detectors": [],
                "error": _exception_failure("account log readiness", exc).as_dict(),
            }

    targets.sort(key=lambda target: target[0].casefold())
    results = []
    if targets:
        with ThreadPoolExecutor(max_workers=min(4, len(targets))) as executor:
            results = list(executor.map(inspect, targets))
    return {
        "subscription": subscription, "resource_group": resource_group, "account": account,
        "checked_at": now.isoformat(), "probe_window_start": (now - timedelta(days=30)).isoformat(),
        "recent_since": (now - timedelta(days=1)).isoformat(),
        "accounts_checked": len(results),
        "accounts_errored": sum(row["status"] != "checked" for row in results),
        "accounts": results,
        "note": (
            "Read-only logging configuration/readability check for NoSQL accounts, not a health verdict. "
            "Recent rows do not prove complete history, sufficient per-container traffic or detector applicability. "
            "Analysis remains available with the sources you can read. No settings or workloads were changed."
        ),
    }

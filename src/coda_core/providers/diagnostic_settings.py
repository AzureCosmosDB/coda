"""Read account log exports and distinguish their configuration age from query activity."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogExport:
    """A category's current destinations and the date their dedicated coverage is known from."""

    status: str
    workspaces: tuple[str, ...]
    since: datetime | None


@dataclass(frozen=True)
class FanoutLogHistory:
    """Shared DX-002/DX-007 log configuration history; never proof of every event."""

    since: datetime | None
    issue: str | None = None

    @classmethod
    def from_exports(cls, exports: dict[str, LogExport]) -> "FanoutLogHistory":
        """Only the required query and request exports establish fan-out history."""
        dates = []
        for table in ("CDBQueryRuntimeStatistics", "CDBDataPlaneRequests"):
            export = exports[table]
            if export.status != "configured" or export.since is None:
                return cls(None, f"{table}: configuration history unverified ({export.status})")
            dates.append(export.since)
        return cls(max(dates))


def read_log_exports(monitor, resource_id: str, table_categories: dict[str, str], **options) -> dict[str, LogExport]:
    """Resolve named categories/groups identically for diagnosis and pre-checks."""
    categories = {}
    for item in monitor.diagnostic_settings_category.list(resource_id, **options):
        if item.category_type == "Logs":
            if not isinstance(item.name, str) or not item.name:
                raise ValueError("Diagnostic category has no name.")
            categories[item.name.casefold()] = {group.casefold() for group in item.category_groups or ()}
    settings = list(monitor.diagnostic_settings.list(resource_id, **options))

    def matches(log, category):
        if type(log.enabled) is not bool:
            raise ValueError("Diagnostic category enabled state is invalid.")
        if not log.enabled:
            return False
        if bool(log.category) == bool(log.category_group):
            raise ValueError("Diagnostic log must name exactly one category or group.")
        if log.category:
            return log.category.casefold() == category
        group = log.category_group.casefold()
        return (group == "alllogs" and category in categories) or group in categories.get(category, ())

    results = {}
    for table, category_name in table_categories.items():
        category = category_name.casefold()
        dedicated, legacy = {}, set()
        other_destination = False
        for setting in settings:
            if not any(matches(log, category) for log in setting.logs or ()):
                continue
            ws = setting.workspace_id
            mode = (setting.log_analytics_destination_type or "").casefold()
            if not ws:
                other_destination = True
            elif not isinstance(ws, str):
                raise ValueError("Diagnostic workspace identity is invalid.")
            elif mode == "dedicated":
                # Creation alone cannot prove the category wasn't enabled by a later edit.
                stamp = getattr(getattr(setting, "system_data", None), "last_modified_at", None)
                dates = dedicated.setdefault(ws, [])
                if isinstance(stamp, datetime) and stamp.utcoffset() is not None:
                    dates.append(stamp)
            elif mode in {"", "azurediagnostics"}:
                legacy.add(ws)
            else:
                raise ValueError("Unknown Log Analytics destination table mode.")
        state = ("configured" if dedicated else "wrong_mode" if legacy else "missing_workspace"
                 if other_destination else "not_configured" if category in categories else "unsupported")
        # A redundant export to the same workspace need not restart its history. Across
        # destinations the reader can select different copies, so require evidence for each.
        since = max(min(dates) for dates in dedicated.values()) if dedicated and all(dedicated.values()) else None
        results[table] = LogExport(state, tuple(sorted(set(dedicated) | legacy)), since)
    return results

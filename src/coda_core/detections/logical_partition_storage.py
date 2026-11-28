"""Optional DX-015 evidence from resource-specific PartitionKeyStatistics, independent of physical skew."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import json

from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import LogAnalyticsProvider, LogAnalyticsQueryError

TABLE = "CDBPartitionKeyStatistics"
CATEGORY = "PartitionKeyStatistics"
KIB_PER_GIB = 1024**2
DEFAULT_LIMIT_GIB = 20
WARNING_GIB = 14
HIGH_GIB = 18
RECENT = timedelta(days=1)
SETUP = ("Enable the PartitionKeyStatistics diagnostic log category on the Cosmos DB account, "
         "send it to Log Analytics in resource-specific mode (CDBPartitionKeyStatistics), "
         "then rerun after samples arrive.")


@dataclass(frozen=True)
class LogicalStorage:
    """A bounded observation, never a list of tenant keys or a claim about unsampled keys."""

    status: str
    message: str
    size_kib: int | None = None
    observed_at: str | None = None
    headroom_to_default_kib: int | None = None


def _query(units: dict[tuple[str, str], datetime | None], window: TimeWindow) -> str:
    """Use latest per full key, not historical peaks or sums of replicas/workspaces.

    Resolve conflicting copies at the latest timestamp as unknown. Return at most four
    aggregate rows per container and no partition key values, including for basic log plans.
    """
    predicates = []
    for (db, name), created in units.items():
        scope = f"DatabaseName == {json.dumps(db)} and CollectionName == {json.dumps(name)}"
        if created and created > window.start:
            scope += f" and TimeGenerated >= datetime({created.isoformat()})"
        predicates.append(f"({scope})")
    return f"""{TABLE}
| where TimeGenerated >= datetime({window.start.isoformat()}) and TimeGenerated < datetime({window.end.isoformat()})
| where {' or '.join(predicates)}
| summarize lo=min(SizeKb), hi=max(SizeKb), bad=countif(isnull(SizeKb) or SizeKb < 0 or isempty(PartitionKey))
    by DatabaseName, CollectionName, PartitionKey, TimeGenerated
| summarize arg_max(TimeGenerated, lo, hi, bad) by DatabaseName, CollectionName, PartitionKey
| extend recent=TimeGenerated >= datetime({(window.end-RECENT).isoformat()}), valid=bad==0 and lo==hi
| summarize TimeGenerated=max(TimeGenerated) by DatabaseName, CollectionName, recent, valid, hi
| summarize arg_max(hi, TimeGenerated) by DatabaseName, CollectionName, recent, valid
| project DatabaseName, CollectionName, recent, valid, size_kib=hi, observed_at=TimeGenerated"""


def _interpret(rows: list[dict], window: TimeWindow) -> LogicalStorage:
    """Compare unrounded KiB using only recent, unambiguous logical observations."""
    if not rows:
        return LogicalStorage("no_samples", "No sampled logical keys were reported in the window; risk is not established.")
    samples = []
    for row in rows:
        stamp = row["observed_at"]
        if (not isinstance(stamp, datetime) or stamp.utcoffset() is None or not window.start <= stamp < window.end
                or type(row["recent"]) is not bool or row["recent"] != (stamp >= window.end - RECENT)):
            raise ValueError("Invalid logical partition sample timestamp")
        if not row["recent"]:
            continue
        size = row["size_kib"]
        if row["valid"] is not True or type(size) is not int or size < 0:
            raise ValueError("Invalid logical partition size")
        samples.append((size, stamp))
    if not samples:
        return LogicalStorage("stale", "Only older logical-key samples were reported; none in the last 24 hours.")
    size, stamp = max(samples)
    level = "high" if size >= HIGH_GIB * KIB_PER_GIB else "warning" if size > WARNING_GIB * KIB_PER_GIB else "observed"
    headroom = max(0, DEFAULT_LIMIT_GIB * KIB_PER_GIB - size)
    message = (f"Largest recent sampled logical partition: approximately {size/KIB_PER_GIB:.2f} GiB "
               f"at {stamp.isoformat()} (about {headroom/KIB_PER_GIB:.2f} GiB of headroom to the default "
               f"{DEFAULT_LIMIT_GIB} GiB limit).")
    if level == "high":
        message += " Check remaining headroom and the applicable limit for this full partition key."
    elif level == "warning":
        message += " Early warning: monitor this key's size and growth."
    return LogicalStorage(level, message, size, stamp.isoformat(), headroom)


def collect(la: LogAnalyticsProvider | None, rid: str, export: str, window: TimeWindow,
            units: dict[tuple[str, str], datetime | None]) -> dict[tuple[str, str], LogicalStorage]:
    """Read enabled logs once per bounded batch; isolate errors and never change a setting."""
    if export == "not_configured":
        default = LogicalStorage("not_configured", f"Logical-key risk not assessed. {SETUP}")
    elif export in {"wrong_mode", "missing_workspace"}:
        default = LogicalStorage(export, f"Logical-key logs are not routed to resource-specific Log Analytics. {SETUP}")
    elif export == "unsupported":
        default = LogicalStorage(export, "Logical-key risk not assessed: this log category is not advertised for the account.")
    elif export != "configured":
        default = LogicalStorage("configuration_unknown", "Logical-key risk not assessed: log configuration could not be verified.")
    elif la is None:
        default = LogicalStorage("no_provider", "Logical-key logging is configured, but no Log Analytics reader is available.")
    else:
        default = None
    if default is not None:
        return dict.fromkeys(units, default)
    result = {}
    keys = sorted(units)
    for offset in range(0, len(keys), 32):
        batch = {key: units[key] for key in keys[offset:offset+32]}
        grouped = {key: [] for key in batch}
        try:
            rows = la.query_resource(rid, _query(batch, window), (window.start, window.end))
            for row in rows:
                grouped[row["DatabaseName"], row["CollectionName"]].append(row)
        except Exception as exc:  # noqa: BLE001 - optional log errors must not suppress physical observations
            if isinstance(exc, LogAnalyticsQueryError) and exc.is_missing_table and TABLE.casefold() in str(exc).casefold():
                error = LogicalStorage("missing_table", "Logging is configured; the logical-key table is not available yet. Check ingestion and table access.")
            elif (getattr(exc, "status_code", None) in (401, 403) or isinstance(exc, PermissionError)
                  or str(getattr(exc, "code", "")).casefold() in {"insufficientaccesserror", "forbidden", "authorizationfailed"}):
                error = LogicalStorage("denied", "Logical-key logging is configured, but access to the log data was denied.")
            else:
                error = LogicalStorage("query_error", f"Logical-key log read failed or was incomplete ({type(exc).__name__}).")
            result.update(dict.fromkeys(batch, error))
            continue
        for key, records in grouped.items():
            try:
                result[key] = _interpret(records, window)
            except (KeyError, TypeError, ValueError):
                result[key] = LogicalStorage("invalid", "Logical-key samples are incomplete or inconsistent; risk not assessed.")
    return result

"""DX-016: Review Strong consistency, or multi-region Bounded Staleness, from ARM configuration.

**Strong** reads use a local replica quorum and cost twice the RU of Session reads even in one
region. Cross-region write latency is a separate multi-region trade-off. ADR-0074 includes known
single-region Strong at the existing Medium severity; single-region Bounded Staleness remains
outside the finding policy. Internal "premium" labels refer to consistency trade-offs, not a SKU.
Session can provide read-your-writes with token continuity, not Strong's global guarantees; changing
consistency requires application review. An account has one default level: Strong OR Bounded
Staleness are alternatives, never a simultaneous-level condition.

This is a **configuration/state** detection whose finding never depends on telemetry. When
five-minute or raw request logs are available, an exact-account absolute-window query enriches a positive
finding with observed read request charge for only the live-validated ``Read``, ``Query``, and
``QueryPlan`` operations. Half that charge is an upper bound, not measured savings, because logs do
not expose per-request consistency overrides. Five-minute totals/counts are preferred; raw logs
remain a compatibility source. No dollar estimate is produced. Read-only /
diagnose-only.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from coda_core.providers.arm import AccountConfig
from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import (
    DataPlaneSource,
    LogAnalyticsProvider,
    primary_destination_filter,
)

# Internal consistency grouping, not a pricing SKU; normalized to lowercase for comparison.
_PREMIUM_LEVELS = {"strong", "boundedstaleness", "bounded_staleness"}
READ_OPERATION_ALLOWLIST = ("Read", "Query", "QueryPlan")
PRODUCTION_WINDOW = timedelta(hours=24)


def _normalize(level: str | None) -> str:
    return (level or "").split(".")[-1].replace("_", "").strip().lower()


def production_window(
    now: datetime, source: DataPlaneSource = DataPlaneSource.RAW,
) -> TimeWindow:
    """Use a bounded recent window for optional read-charge enrichment."""
    anchor = source.anchor(now)
    return TimeWindow(anchor - PRODUCTION_WINDOW, anchor)


def _kql_string(value: str) -> str:
    """Quote one trusted ARM identifier as a KQL string literal."""
    return "'" + value.replace("'", "''") + "'"


def read_request_charge_kql(
    resource_id: str, window: TimeWindow, source: DataPlaneSource = DataPlaneSource.RAW,
) -> str:
    """Build the exact-account, absolute ``[start,end)`` read-charge query."""
    source.validate_window(window)
    operations = ", ".join(f'"{name}"' for name in READ_OPERATION_ALLOWLIST)
    invalid_count = (
        " or request_charge_value < 0 or isnull(RequestCount) or RequestCount <= 0 "
        "or floor(RequestCount, 1.0) != RequestCount"
        if source is DataPlaneSource.FIVE_MINUTE else ""
    )
    return f"""{source.value}
{primary_destination_filter(source.value, window)}
| where TimeGenerated >= datetime({window.start.isoformat()})
    and TimeGenerated < datetime({window.end.isoformat()})
| where _ResourceId =~ {_kql_string(resource_id)}
| where OperationName in ({operations})
| extend request_charge_value=todouble({source.charge})
| summarize request_count={source.count},
    invalid_request_charge_count=countif(isnull(request_charge_value){invalid_count}),
    request_charge=sum(request_charge_value) by OperationName
| project operation_name=OperationName, request_count, invalid_request_charge_count, request_charge
"""


def observe_read_request_charge(
    la: LogAnalyticsProvider,
    resource_id: str,
    window: TimeWindow,
    source: DataPlaneSource = DataPlaneSource.RAW,
) -> dict:
    """Return audited read RequestCharge evidence without interpreting it as savings."""
    source.validate_window(window)
    rows = la.query_resource(
        resource_id,
        read_request_charge_kql(resource_id, window, source),
        (window.start, window.end),
    )
    breakdown: dict[str, dict[str, float | int]] = {}
    total_ru = 0.0
    total_requests = 0
    for row in rows:
        operation = row.get("operation_name")
        if operation not in READ_OPERATION_ALLOWLIST:
            raise ValueError(f"Unexpected read operation in query result: {operation!r}")
        if operation in breakdown:
            raise ValueError(f"Duplicate read operation in query result: {operation!r}")
        try:
            request_charge = float(row["request_charge"])
            request_count_value = float(row["request_count"])
            invalid_charge_count = int(row["invalid_request_charge_count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Read request-charge query returned an incomplete aggregate") from exc
        if (
            not math.isfinite(request_charge)
            or request_charge < 0
            or not math.isfinite(request_count_value)
            or request_count_value <= 0
            or not request_count_value.is_integer()
            or invalid_charge_count != 0
        ):
            raise ValueError("Read request-charge query returned an invalid aggregate")
        request_count = int(request_count_value)
        breakdown[operation] = {
            "request_count": request_count,
            "request_charge_ru": round(request_charge, 6),
        }
        total_ru += request_charge
        total_requests += request_count

    observed = round(total_ru, 6)
    return {
        "status": "observed" if total_requests else "no_observations",
        "source": source.value,
        "account_resource_id": resource_id,
        "observation_window": {
            "start_utc": window.start.isoformat(),
            "end_utc": window.end.isoformat(),
            "semantics": "[start,end)",
        },
        "validated_read_operations": list(READ_OPERATION_ALLOWLIST),
        "operation_breakdown": breakdown,
        "observed_read_request_count": total_requests,
        "observed_read_request_charge_ru": observed,
        "upper_bound_avoidable_read_request_charge_ru": round(observed / 2.0, 6),
        "upper_bound_reason": (
            "Reads at Strong or Bounded Staleness can cost twice weaker-consistency reads. "
            "An account has one default level; request logs do not expose per-request "
            "consistency overrides."
        ),
        "dollar_estimate": None,
    }


@dataclass(frozen=True)
class ConsistencyVerdict:
    is_expensive: bool
    # premium_multi_region | strong_single_region | single_region | default_or_relaxed | unknown
    root_cause: str
    consistency_level: str | None
    region_count: int
    severity: str  # medium | low | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def detect_expensive_consistency(config: AccountConfig) -> ConsistencyVerdict:
    """Review Strong read cost in known regions without expanding single-region Bounded policy."""
    level = _normalize(config.default_consistency_level)
    method = {"consistency_level": config.default_consistency_level,
              "region_count": config.region_count}

    def verdict(**kw) -> ConsistencyVerdict:
        base = dict(is_expensive=False, root_cause="default_or_relaxed", severity="none",
                    consistency_level=config.default_consistency_level,
                    region_count=config.region_count, recommended_action="", methodology=method)
        base.update(kw)
        return ConsistencyVerdict(**base)

    if not level:
        return verdict(root_cause="unknown")
    if level not in _PREMIUM_LEVELS:
        return verdict(root_cause="default_or_relaxed")  # Session / Eventual / ConsistentPrefix
    is_strong = level == "strong"
    single_region_strong = is_strong and config.region_count == 1
    if config.region_count < 2 and not single_region_strong:
        return verdict(root_cause="single_region")

    location = "in 1 region" if single_region_strong else f"across {config.region_count} regions"
    if single_region_strong:
        write_tradeoff = "There is no cross-region write-latency cost in this single-region account. "
    elif is_strong:
        write_tradeoff = (
            "Across multiple regions, Strong also makes writes wait on other regions, raising "
            "write latency and tightening availability. "
        )
    else:
        write_tradeoff = (
            "Across multiple regions, Bounded Staleness constrains replication lag and can "
            "throttle writes when the bound is exceeded. "
        )
    return verdict(
        is_expensive=True,
        root_cause="strong_single_region" if single_region_strong else "premium_multi_region",
        severity=("medium" if is_strong else "low"),
        recommended_action=(
            f"This account has one default consistency level: "
            f"{config.default_consistency_level} ({location}). "
            "Reads using this level use a local replica quorum and cost twice the RU of Session "
            f"reads. {write_tradeoff}"
            "If application requirements permit, evaluate Session. It provides read-your-writes "
            "with the latest relevant opaque, partition-bound SessionToken; a reused SDK client "
            "manages its session tokens. For a load-balanced web app, capture the Cosmos response "
            "SessionToken, return it through the web tier to the end-user client in a cookie "
            "(or equivalent client context), then receive it on a later web request. Pass the "
            "token in the Cosmos request options of whichever SDK instance handles that request; "
            "no direct SDK-to-SDK synchronization is required. Session is not equivalent to "
            "Strong's global guarantees. Check per-request consistency overrides and validate "
            "application requirements before changing the account default."
        ),
    )

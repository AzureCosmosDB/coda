"""DX-016: Expensive consistency level on a multi-region account.

Cosmos DB's default consistency is **Session**, which suits most workloads. **Strong** and
**Bounded Staleness** trade latency and availability for stronger guarantees: across multiple regions
they make writes wait on additional regions, raising write latency and tightening the availability
envelope. An account that runs a premium consistency level across ≥2 regions without needing those
guarantees is paying that latency/availability cost for nothing.

This is a **configuration/state** detection whose finding never depends on telemetry. When
``CDBDataPlaneRequests`` is available, an exact-account absolute-window query enriches a positive
finding with observed read request charge for only the live-validated ``Read``, ``Query``, and
``QueryPlan`` operations. Half that charge is an upper bound, not measured savings, because logs do
not expose per-request consistency overrides. No dollar estimate is produced. Read-only /
diagnose-only.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from coda_core.providers.arm import AccountConfig
from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import LogAnalyticsProvider

# Consistency levels stronger than the Session default, normalised to lowercase for comparison.
_PREMIUM_LEVELS = {"strong", "boundedstaleness", "bounded_staleness"}
READ_OPERATION_ALLOWLIST = ("Read", "Query", "QueryPlan")
PRODUCTION_WINDOW = timedelta(hours=24)


def _normalize(level: str | None) -> str:
    return (level or "").split(".")[-1].replace("_", "").strip().lower()


def production_window(now: datetime) -> TimeWindow:
    """Use a bounded recent window for optional read-charge enrichment."""
    return TimeWindow(now - PRODUCTION_WINDOW, now)


def _kql_string(value: str) -> str:
    """Quote one trusted ARM identifier as a KQL string literal."""
    return "'" + value.replace("'", "''") + "'"


def read_request_charge_kql(resource_id: str, window: TimeWindow) -> str:
    """Build the exact-account, absolute ``[start,end)`` read-charge query."""
    operations = ", ".join(f'"{name}"' for name in READ_OPERATION_ALLOWLIST)
    return f"""CDBDataPlaneRequests
| where TimeGenerated >= datetime({window.start.isoformat()})
    and TimeGenerated < datetime({window.end.isoformat()})
| where _ResourceId =~ {_kql_string(resource_id)}
| where OperationName in ({operations})
| extend request_charge_value=todouble(RequestCharge)
| summarize request_count=count(),
    invalid_request_charge_count=countif(isnull(request_charge_value)),
    request_charge=sum(request_charge_value) by OperationName
| project operation_name=OperationName, request_count, invalid_request_charge_count, request_charge
"""


def observe_read_request_charge(
    la: LogAnalyticsProvider,
    resource_id: str,
    window: TimeWindow,
) -> dict:
    """Return audited read RequestCharge evidence without interpreting it as savings."""
    rows = la.query_resource(
        resource_id,
        read_request_charge_kql(resource_id, window),
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
            request_count = int(row["request_count"])
            invalid_charge_count = int(row["invalid_request_charge_count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Read request-charge query returned an incomplete aggregate") from exc
        if (
            not math.isfinite(request_charge)
            or request_charge < 0
            or request_count <= 0
            or invalid_charge_count != 0
        ):
            raise ValueError("Read request-charge query returned an invalid aggregate")
        breakdown[operation] = {
            "request_count": request_count,
            "request_charge_ru": round(request_charge, 6),
        }
        total_ru += request_charge
        total_requests += request_count

    observed = round(total_ru, 6)
    return {
        "status": "observed" if total_requests else "no_observations",
        "source": "CDBDataPlaneRequests",
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
            "Strong reads can cost up to twice weaker-consistency reads, but "
            "CDBDataPlaneRequests does not expose per-request consistency overrides."
        ),
        "dollar_estimate": None,
    }


@dataclass(frozen=True)
class ConsistencyVerdict:
    is_expensive: bool
    # premium_multi_region | single_region | default_or_relaxed | unknown
    root_cause: str
    consistency_level: str | None
    region_count: int
    severity: str  # medium | low | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def detect_expensive_consistency(config: AccountConfig) -> ConsistencyVerdict:
    """Classify an account's consistency configuration (pure; ARM config in, verdict out)."""
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
    if config.region_count < 2:
        # Premium consistency on a single region is local — the cross-region latency cost doesn't apply.
        return verdict(root_cause="single_region")

    is_strong = level == "strong"
    return verdict(
        is_expensive=True, root_cause="premium_multi_region",
        severity=("medium" if is_strong else "low"),
        recommended_action=(
            f"This account uses {config.default_consistency_level} consistency across "
            f"{config.region_count} regions. Across multiple regions this level raises write latency "
            f"and tightens availability (Strong makes writes wait on additional regions). The default "
            f"Session consistency is sufficient for most workloads. Confirm the application genuinely "
            f"needs {config.default_consistency_level}; if not, relax to Session (or "
            f"Bounded Staleness) — the application's tolerance must be validated before changing."
        ),
    )

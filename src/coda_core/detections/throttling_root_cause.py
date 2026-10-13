"""DX-021: Throttling root-cause decomposition (which operations are being throttled).

DX-005 (provisioned) and DX-018 (serverless) answer *"is this account/container throttling?"*. DX-021
adds the **root cause**: of the 429s an account is taking, **which operation category** dominates —
because the fix differs completely by category:

* **writes** (Create/Upsert/Replace/Delete/Patch/Batch) — bulk/batch ingestion outrunning capacity;
  fix with the bulk executor / client-side throughput control / spreading the load (see DX-010).
* **reads** (Read) — point reads throttling usually means a hot partition (DX-006) or genuine
  under-provisioning (DX-005), not the read path itself.
* **queries** (Query/QueryPlan) — expensive or cross-partition fan-out (DX-002 / DX-007); add a
  partition-key filter or an index rather than only adding RU/s.

This reads **Azure Monitor Metrics only** (`TotalRequests` split by `StatusCode` and by `OperationType`
filtered to `StatusCode=429`) — no Log Analytics. It is **advisory** (ADR-0012): it points at the
throttled operation category; app-level attribution (per client `UserAgent`) is a Log-Analytics
enrichment tracked separately. Read-only. Thresholds are **proposals** (registry `threshold_status`).

Closes the `throttling_root_cause` gap from the cosmic-kusto coverage analysis
(`docs/exploration/cosmic-kusto-gap-buildability.md`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import timedelta

from coda_core.providers.base import TimeWindow

# Proposed thresholds (honest by default: registry marks DX-021 `proposal`).
MIN_TOTAL_REQUESTS = 1000       # below this the throttle rate is too noisy to decompose
THROTTLE_RATE_PCT = 1.0         # only decompose when throttling is material (DX-005 owns the verdict)
SEVERITY_HIGH_PCT = 20.0        # mirrors DX-005's reliability severity model
SEVERITY_MEDIUM_PCT = 5.0

# OperationType → (category, tailored guidance). Categories collapse the raw op names.
_WRITE_OPS = {"create", "upsert", "replace", "delete", "patch", "batch", "executebatch"}
_READ_OPS = {"read", "head"}
_QUERY_OPS = {"query", "queryplan", "readfeed"}
_EXEC_OPS = {"execute", "executejavascript", "executestoredprocedure"}

_CATEGORY_GUIDANCE = {
    "write": ("write", "bulk/batch ingestion is outrunning capacity — use the bulk executor or "
                       "client-side throughput control and spread writes over time (see DX-010), "
                       "rather than only raising RU/s"),
    "read": ("read", "point reads are throttling — this usually means a hot partition (DX-006) or "
                     "genuine under-provisioning (DX-005), not the read path itself"),
    "query": ("query", "query load is throttling — check for cross-partition fan-out / expensive "
                       "queries (DX-002 / DX-007) and add a partition-key filter or index before "
                       "adding RU/s"),
    "execute": ("execute", "stored-procedure / server-side execution is throttling — review the "
                          "procedure's RU cost and call rate"),
    "other": ("other", "review the dominant operation's call rate and cost"),
}


def production_window() -> TimeWindow:
    """Throttling is a current-state signal — a 7-day, hourly window (mirrors DX-005)."""
    return TimeWindow.trailing(timedelta(days=7), granularity=timedelta(hours=1))


def _category_of(operation_type: str) -> str:
    op = (operation_type or "").strip().lower()
    if op in _WRITE_OPS:
        return "write"
    if op in _READ_OPS:
        return "read"
    if op in _QUERY_OPS:
        return "query"
    if op in _EXEC_OPS:
        return "execute"
    return "other"


@dataclass(frozen=True)
class ThrottlingRootCauseVerdict:
    is_finding: bool
    # decomposed | not_throttling | too_few_requests
    root_cause: str
    severity: str  # high | medium | low | none
    total_requests: int
    total_throttled: int
    throttle_rate_pct: float
    dominant_operation: str | None
    dominant_category: str | None
    dominant_share_pct: float       # dominant op's share of the 429s
    category_share_pct: dict[str, float]  # 429 share by category
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def detect_throttling_root_cause(
    total_requests: int, total_throttled: int, op_throttled_counts: dict
) -> ThrottlingRootCauseVerdict:
    """Decompose an account's 429s by operation category (pure; counts in, verdict out)."""
    total_requests = int(total_requests or 0)
    total_throttled = int(total_throttled or 0)
    # Normalise the {operation_type: 429_count} map.
    ops: dict[str, int] = {}
    for k, v in (op_throttled_counts or {}).items():
        try:
            n = int(v or 0)
        except (TypeError, ValueError):
            continue
        if n > 0 and k:
            ops[str(k)] = n
    rate = (100.0 * total_throttled / total_requests) if total_requests else 0.0

    # Aggregate 429s by category.
    cat_counts: dict[str, int] = {}
    for op, n in ops.items():
        cat_counts[_category_of(op)] = cat_counts.get(_category_of(op), 0) + n
    cat_share = {c: round(100.0 * n / total_throttled, 2) for c, n in cat_counts.items()} if total_throttled else {}

    method = {
        "total_requests": total_requests, "total_throttled": total_throttled,
        "min_total_requests": MIN_TOTAL_REQUESTS, "throttle_rate_pct_threshold": THROTTLE_RATE_PCT,
        "op_throttled_counts": dict(sorted(ops.items())),
    }

    def verdict(**kw) -> ThrottlingRootCauseVerdict:
        base = dict(
            is_finding=False, root_cause="not_throttling", severity="none",
            total_requests=total_requests, total_throttled=total_throttled,
            throttle_rate_pct=round(rate, 2), dominant_operation=None, dominant_category=None,
            dominant_share_pct=0.0, category_share_pct=cat_share, recommended_action="",
            methodology=method,
        )
        base.update(kw)
        return ThrottlingRootCauseVerdict(**base)

    if total_requests < MIN_TOTAL_REQUESTS:
        return verdict(root_cause="too_few_requests")
    if total_throttled == 0 or rate < THROTTLE_RATE_PCT or not ops:
        return verdict(root_cause="not_throttling")

    dominant_op = max(ops, key=ops.get)
    dominant_share = 100.0 * ops[dominant_op] / total_throttled
    category = _category_of(dominant_op)
    _, guidance = _CATEGORY_GUIDANCE[category]
    severity = ("high" if rate >= SEVERITY_HIGH_PCT
                else "medium" if rate >= SEVERITY_MEDIUM_PCT else "low")
    action = (
        f"{rate:.1f}% of requests were throttled (429). {dominant_share:.0f}% of the throttling is on "
        f"'{dominant_op}' ({category}) operations: {guidance}."
    )
    return verdict(
        is_finding=True, root_cause="decomposed", severity=severity,
        dominant_operation=dominant_op, dominant_category=category,
        dominant_share_pct=round(dominant_share, 2), recommended_action=action,
    )

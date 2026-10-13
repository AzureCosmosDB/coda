"""DX-020: Error-code analysis (non-throttling hard errors).

Throttling (HTTP 429) is its own story — DX-005 (provisioned) and DX-018 (serverless) own it. But a
Cosmos account can also return a material share of **non-429** errors that signal an
**application / SDK / configuration** problem rather than a capacity one, and adding RU/s won't fix
any of them:

* **400 Bad Request** — malformed requests or invalid queries (an app/SDK bug).
* **404 Not Found** — read-before-write or lookups for items that don't exist (often *expected*, but a
  high rate can mean a broken access pattern).
* **409 Conflict** — creating items with an id that already exists.
* **412 Precondition Failed** — optimistic-concurrency (ETag) contention on hot items.
* **408 / 449** — request timeout / "retry with" concurrency retry.
* **5xx** — service-side errors.

This detection reads **Azure Monitor Metrics only** (`TotalRequests` split by `StatusCode`, Count) —
no Log Analytics required — so it runs immediately. It is **advisory** (ADR-0012): it surfaces the
error mix and points at the app/SDK/config, and asserts no dollar or RU/s figure. Read-only /
diagnose-only. Thresholds are **proposals** (registry `threshold_status`) pending fleet grounding.

Data source: `AzureMonitorMetricsProvider.get_metric_split(TotalRequests, split_dimension=StatusCode,
aggregation=Count)`. Closes the `error_analysis` gap from the cosmic-kusto coverage analysis
(`docs/exploration/cosmic-kusto-gap-buildability.md`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import timedelta

from coda_core.providers.base import TimeWindow

# --- Proposed thresholds (honest by default: registry marks DX-020 `proposal`) ---------
# Minimum request volume below which an error *rate* is too noisy to judge (mirrors DX-005).
MIN_TOTAL_REQUESTS = 1000
# Fire when the non-429 hard-error share of all requests reaches this floor.
HARD_ERROR_RATE_PCT = 1.0
# Severity cutoffs on the hard-error rate (proposed; parallels the DX-005 reliability model).
SEVERITY_HIGH_PCT = 10.0
SEVERITY_MEDIUM_PCT = 5.0

# HTTP status → short, human-readable meaning + tailored guidance. Only non-429 client/server errors.
_ERROR_MEANINGS: dict[int, str] = {
    400: "Bad Request — malformed requests or invalid queries (application/SDK issue)",
    401: "Unauthorized — authentication failures",
    403: "Forbidden — authorization/RBAC or firewall failures",
    404: "Not Found — read-before-write or lookups for missing items (often expected; confirm intended)",
    408: "Request Timeout",
    409: "Conflict — creating an item with an id that already exists",
    412: "Precondition Failed — optimistic-concurrency (ETag) contention on hot items",
    413: "Request Entity Too Large — payload exceeds limits",
    449: "Retry With — transient concurrency retry",
    500: "Internal Server Error — service-side",
    503: "Service Unavailable — service-side or connectivity",
}


def production_window() -> TimeWindow:
    """Errors are a current-state reliability signal — a 7-day, hourly window (mirrors DX-005)."""
    return TimeWindow.trailing(timedelta(days=7), granularity=timedelta(hours=1))


def _is_hard_error(code: int) -> bool:
    """A non-429 client/server error (429 throttling is DX-005/DX-018's domain; 2xx/3xx are fine)."""
    return code != 429 and code >= 400


@dataclass(frozen=True)
class ErrorAnalysisVerdict:
    is_finding: bool
    # has_errors | too_few_requests | clean
    root_cause: str
    severity: str  # high | medium | low | none
    total_requests: int
    hard_error_requests: int
    hard_error_rate_pct: float
    dominant_code: int | None
    dominant_rate_pct: float
    category_rates_pct: dict[str, float]  # e.g. {"400": 4.6, "404": 0.2}
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _parse_counts(counts: dict) -> dict[int, int]:
    """Normalise a {status_code_str: count} map to {int_code: int_count}, dropping junk keys."""
    out: dict[int, int] = {}
    for k, v in (counts or {}).items():
        try:
            code = int(str(k).strip())
            n = int(v or 0)
        except (TypeError, ValueError):
            continue
        if n > 0:
            out[code] = out.get(code, 0) + n
    return out


def detect_error_patterns(status_code_counts: dict) -> ErrorAnalysisVerdict:
    """Classify an account's non-429 error mix (pure; status-code counts in, verdict out)."""
    counts = _parse_counts(status_code_counts)
    total = sum(counts.values())

    hard = {c: n for c, n in counts.items() if _is_hard_error(c)}
    hard_total = sum(hard.values())
    rate = (100.0 * hard_total / total) if total else 0.0
    category_rates = {str(c): round(100.0 * n / total, 2) for c, n in sorted(hard.items()) if total}
    method = {
        "total_requests": total,
        "hard_error_requests": hard_total,
        "min_total_requests": MIN_TOTAL_REQUESTS,
        "hard_error_rate_pct_threshold": HARD_ERROR_RATE_PCT,
        "status_code_counts": {str(c): n for c, n in sorted(counts.items())},
    }

    def verdict(**kw) -> ErrorAnalysisVerdict:
        base = dict(
            is_finding=False, root_cause="clean", severity="none", total_requests=total,
            hard_error_requests=hard_total, hard_error_rate_pct=round(rate, 2),
            dominant_code=None, dominant_rate_pct=0.0, category_rates_pct=category_rates,
            recommended_action="", methodology=method,
        )
        base.update(kw)
        return ErrorAnalysisVerdict(**base)

    if total < MIN_TOTAL_REQUESTS:
        return verdict(root_cause="too_few_requests")
    if hard_total == 0 or rate < HARD_ERROR_RATE_PCT:
        return verdict(root_cause="clean")

    dominant_code = max(hard, key=hard.get)
    dominant_rate = 100.0 * hard[dominant_code] / total
    severity = ("high" if rate >= SEVERITY_HIGH_PCT
                else "medium" if rate >= SEVERITY_MEDIUM_PCT else "low")
    dom_meaning = _ERROR_MEANINGS.get(dominant_code, f"HTTP {dominant_code}")
    action = (
        f"{rate:.1f}% of requests returned non-throttling errors over the window "
        f"(dominated by HTTP {dominant_code} at {dominant_rate:.1f}% — {dom_meaning}). These are "
        f"application/SDK/configuration issues, not capacity — adding RU/s will not help. Investigate "
        f"the source (request formation, access pattern, concurrency/ETag usage, or auth/config) and "
        f"fix it client-side."
    )
    return verdict(
        is_finding=True, root_cause="has_errors", severity=severity,
        dominant_code=dominant_code, dominant_rate_pct=round(dominant_rate, 2),
        recommended_action=action,
    )

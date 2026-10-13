"""DX-014: Provisioned → Serverless candidate (account-scoped).

Serverless is a per-account capacity mode that bills per RU consumed with no provisioned floor — it
wins for **low, sporadic** workloads with long idle stretches. This detection flags an account whose
total consumed throughput is low and bursty (a low average-to-peak ratio) as a candidate to evaluate
serverless.

Important constraints make this a **migration-class, high-confidence-only** recommendation (per the
right-sizing family doc, verified against Microsoft Learn):
* Conversion is **one-way**: there is no in-place provisioned → serverless path, so it means creating a
  **new** serverless account and migrating data.
* Serverless is **single-region**, has **no shared-throughput databases**, and caps at **5,000 RU/s per
  physical partition**.

Signal: the account-total **Request Units consumed** (Azure Monitor ``TotalRequestUnits``) over the
window — no per-container filter, no Log Analytics. Qualitative per ADR-0012 (no cost figure); the
benefit is a pricing model change, and the customer must validate the constraints fit. Read-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow

PRODUCTION_WINDOW_DAYS = 30
GRANULARITY = timedelta(hours=1)
# Serverless capacity is 5,000 RU/s *per physical partition* (total = partitions × 5,000). We gate the
# candidate's **account-total peak** at this single-partition figure as a deliberately CONSERVATIVE bar:
# (a) serverless gives no throughput/latency guarantee, so suggesting it for a >5,000 RU/s workload is
# risky; and (b) realising partitions × 5,000 needs even key distribution we can't verify. A workload
# that peaks above this is steered away from serverless (a safe false-negative). Raise this as the
# serverless RU ceiling is lifted (see docs/exploration / serverless telemetry notes).
SERVERLESS_CONTAINER_CEILING_RU = 5000.0


def production_window(now: datetime | None = None) -> TimeWindow:
    anchor = now or datetime.now(timezone.utc)
    return TimeWindow(anchor - timedelta(days=PRODUCTION_WINDOW_DAYS), anchor, GRANULARITY)


@dataclass(frozen=True)
class ServerlessCandidateConfig:
    sporadic_ratio: float = 0.10      # avg/peak below this = sporadic (long idle stretches)
    peak_ceiling_ru: float = SERVERLESS_CONTAINER_CEILING_RU  # conservative single-partition fit bar
    peak_floor_ru: float = 10.0       # some real usage (a fully idle account is DX-004, not this)
    min_points: int = 24              # need enough history to judge the shape


@dataclass(frozen=True)
class ServerlessCandidateVerdict:
    is_candidate: bool
    avg_ru_per_s: float
    peak_ru_per_s: float
    avg_to_peak: float
    severity: str  # low | none
    # serverless_candidate | steady_load | too_high | idle_or_empty | insufficient_data
    root_cause: str
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def classify(
    avg_ru_s: float, peak_ru_s: float, sample_count: int,
    config: ServerlessCandidateConfig | None = None,
) -> ServerlessCandidateVerdict:
    cfg = config or ServerlessCandidateConfig()
    ratio = (avg_ru_s / peak_ru_s) if peak_ru_s > 0 else 0.0
    method = {"thresholds": {"sporadic_ratio": cfg.sporadic_ratio,
                             "peak_ceiling_ru": cfg.peak_ceiling_ru,
                             "peak_floor_ru": cfg.peak_floor_ru}}

    def verdict(**kw) -> ServerlessCandidateVerdict:
        base = dict(is_candidate=False, avg_ru_per_s=round(avg_ru_s, 1),
                    peak_ru_per_s=round(peak_ru_s, 1), avg_to_peak=round(ratio, 3),
                    severity="none", root_cause="steady_load", recommended_action="",
                    methodology=method)
        base.update(kw)
        return ServerlessCandidateVerdict(**base)

    if sample_count < cfg.min_points:
        return verdict(root_cause="insufficient_data")
    if peak_ru_s < cfg.peak_floor_ru:
        return verdict(root_cause="idle_or_empty")   # ~no usage -> DX-004 decommission, not serverless
    if peak_ru_s > cfg.peak_ceiling_ru:
        # Above the conservative single-partition serverless bar — steer away (safe false-negative).
        return verdict(root_cause="too_high")
    if ratio >= cfg.sporadic_ratio:
        return verdict(root_cause="steady_load")      # not sporadic enough to win on serverless

    return verdict(
        is_candidate=True, root_cause="serverless_candidate", severity="low",
        recommended_action=(
            f"Account throughput is low and sporadic (peak {peak_ru_s:.0f} RU/s, average "
            f"{avg_ru_s:.0f} RU/s — a {ratio * 100:.0f}% average-to-peak ratio with long idle "
            f"stretches). Serverless (pay-per-RU, no provisioned floor) may cost less for this shape. "
            f"This is migration-class — serverless is a new, single-region account (not an in-place "
            f"switch) with no shared-throughput databases and a 5,000 RU/s per-partition cap — validate "
            f"those fit before migrating data to a new serverless account."
        ),
    )


def detect_serverless_candidate(
    metrics: AzureMonitorMetricsProvider,
    account_resource_id: str,
    window: TimeWindow,
    *,
    is_serverless: bool = False,
    config: ServerlessCandidateConfig | None = None,
) -> ServerlessCandidateVerdict:
    """End-to-end DX-014 for one account: judge the account-total consumed-RU shape.

    Guard: an account that is **already serverless** is never a candidate — recommending serverless to
    a serverless account is nonsensical. This is the one detector that would otherwise misfire on a
    serverless account (the container detectors skip it — serverless containers have no throughput
    offer — but DX-014 is account-level and a serverless account does report consumed RU).
    """
    if is_serverless:
        return ServerlessCandidateVerdict(
            is_candidate=False, avg_ru_per_s=0.0, peak_ru_per_s=0.0, avg_to_peak=0.0, severity="none",
            root_cause="already_serverless", recommended_action="",
            methodology={"guard": "account is already serverless; DX-014 not applicable"},
        )
    # Account-total RU consumed per bucket (no DatabaseName/CollectionName filter).
    series = metrics.get_metric(account_resource_id, "TotalRequestUnits", window, aggregation="Total")
    bucket_seconds = window.granularity.total_seconds() or 3600.0
    ru_per_s = [v / bucket_seconds for v in series.values()]
    if not ru_per_s:
        return classify(0.0, 0.0, 0, config)
    avg_ru_s = sum(ru_per_s) / len(ru_per_s)
    peak_ru_s = max(ru_per_s)
    return classify(avg_ru_s, peak_ru_s, len(ru_per_s), config)

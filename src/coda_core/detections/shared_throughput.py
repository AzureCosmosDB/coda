"""DX-003: Shared-throughput starvation.

In a shared-throughput database, every container draws from one database-level RU/s pool. A single
container can monopolise that pool, **starving its siblings** — they throttle (429) despite consuming
little, while the database as a whole is at its cap. This is distinct from global under-provisioning
(DX-005): the database *has* capacity, it's just unfairly distributed.

Signal & data source: **Log Analytics** ``CDBDataPlaneRequests5M`` when available, otherwise
``CDBDataPlaneRequests``. Aggregate rows use ``RequestCount`` and ``TotalRequestCharge``;
raw rows use row counts and ``RequestCharge``. Both retain per-collection volume, 429 rate, and RU
within the shared database. Trigger: the pool is throttling **and** consumption is concentrated on one
collection (the monopoliser) **and** a low-consumption sibling is throttled (the victim).

Honest telemetry limit (gap **D5**): the exact *internal* RU allocation per collection within a shared
pool is not exposed in any customer table. CODA detects the **symptom** (a 429 + consumption disparity)
and names the likely monopoliser/victim, but cannot show the precise pool split.

Capability gating distinguishes unavailable request-log sources from a configured selected table
with no rows in this detector's window. The latter is an insufficient-data abstention, not a request to
enable diagnostics. Read-only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import DataPlaneSource, LogAnalyticsProvider


# Shared-pool throttling is a present-tense signal; a 1-day window over the data-plane logs is enough.
def production_window(
    now: datetime | None = None, source: DataPlaneSource = DataPlaneSource.RAW,
) -> TimeWindow:
    """Keep the full production day, ending at a complete bucket for aggregated logs."""
    anchor = source.anchor(now or datetime.now(timezone.utc))
    return TimeWindow(anchor - timedelta(days=1), anchor, timedelta(hours=1))


def traffic_kql(
    database: str, source: DataPlaneSource = DataPlaneSource.RAW,
    window: TimeWindow | None = None,
) -> str:
    """KQL for DX-003's per-collection traffic in one shared-throughput database."""
    safe_db = database.replace("'", "")
    return (
        source.query_table(window)
        + f"| where DatabaseName == '{safe_db}' and isnotempty(CollectionName) "
        f"| summarize requests = {source.count}, "
        f"throttled = {source.count_if('StatusCode == 429')}, "
        f"ru = sum({source.charge}){source.invalid_rows} by CollectionName"
    )


@dataclass(frozen=True)
class CollectionTraffic:
    """One collection's data-plane traffic within a shared database, over the window."""

    name: str
    requests: int
    throttled_429: int
    ru_consumed: float

    @property
    def throttle_rate_pct(self) -> float:
        return (100.0 * self.throttled_429 / self.requests) if self.requests else 0.0


@dataclass(frozen=True)
class SharedThroughputConfig:
    min_requests: int = 100         # a collection below this is "inactive" for the window
    pool_throttle_pct: float = 5.0  # database-wide 429 rate at/above this = pool under pressure
    dominance_pct: float = 60.0     # one collection consuming >= this share of pool RU = monopoliser
    victim_throttle_pct: float = 5.0  # a starved sibling throttles at/above this
    victim_share_pct: float = 20.0    # ...while consuming <= this share of pool RU


@dataclass(frozen=True)
class SharedThroughputVerdict:
    is_starvation: bool
    # starvation | no_disparity | not_throttling | single_collection | insufficient_data |
    # query_error
    root_cause: str
    database: str
    collection_count: int
    pool_throttle_rate_pct: float
    monopolizer: str | None
    monopolizer_ru_share_pct: float
    victim: str | None
    victim_throttle_rate_pct: float
    severity: str  # high | medium | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _abstain(database: str, root_cause: str, detail: str) -> SharedThroughputVerdict:
    method = {"abstained": detail}
    if root_cause == "log_analytics_unavailable":
        method["la_unavailable"] = True
    return SharedThroughputVerdict(
        is_starvation=False, root_cause=root_cause, database=database, collection_count=0,
        pool_throttle_rate_pct=0.0, monopolizer=None, monopolizer_ru_share_pct=0.0, victim=None,
        victim_throttle_rate_pct=0.0, severity="none", recommended_action="",
        methodology=method,
    )


def classify(
    database: str, collections: list[CollectionTraffic], shared_ru: float,
    config: SharedThroughputConfig | None = None,
) -> SharedThroughputVerdict:
    """Map per-collection shared-pool traffic to a starvation verdict (pure)."""
    cfg = config or SharedThroughputConfig()
    active = [c for c in collections if c.requests >= cfg.min_requests]
    ru_total = sum(c.ru_consumed for c in active)
    req_total = sum(c.requests for c in active)
    thr_total = sum(c.throttled_429 for c in active)
    pool_rate = (100.0 * thr_total / req_total) if req_total else 0.0

    def verdict(**kw) -> SharedThroughputVerdict:
        base = dict(
            is_starvation=False, root_cause="no_disparity", database=database,
            collection_count=len(active), pool_throttle_rate_pct=round(pool_rate, 2),
            monopolizer=None, monopolizer_ru_share_pct=0.0, victim=None,
            victim_throttle_rate_pct=0.0, severity="none", recommended_action="",
            methodology={"thresholds": {"pool_throttle_pct": cfg.pool_throttle_pct,
                                        "dominance_pct": cfg.dominance_pct,
                                        "victim_throttle_pct": cfg.victim_throttle_pct,
                                        "victim_share_pct": cfg.victim_share_pct},
                         "shared_ru": shared_ru, "active_collections": len(active),
                         "note": "Internal per-collection RU allocation is not exposed (gap D5); "
                                 "starvation is inferred from the 429 + consumption disparity."},
        )
        base.update(kw)
        return SharedThroughputVerdict(**base)

    if len(active) < 2:
        return verdict(root_cause="single_collection")
    if pool_rate < cfg.pool_throttle_pct:
        return verdict(root_cause="not_throttling")
    if ru_total <= 0:
        return verdict(root_cause="insufficient_data")

    shares = {c.name: 100.0 * c.ru_consumed / ru_total for c in active}
    monopolizer = max(active, key=lambda c: shares[c.name])
    mono_share = shares[monopolizer.name]
    # Victim: a different collection that throttles materially while consuming little of the pool.
    victims = [
        c for c in active
        if c.name != monopolizer.name
        and c.throttle_rate_pct >= cfg.victim_throttle_pct
        and shares[c.name] <= cfg.victim_share_pct
    ]
    if mono_share < cfg.dominance_pct or not victims:
        return verdict(root_cause="no_disparity",
                       monopolizer=monopolizer.name, monopolizer_ru_share_pct=round(mono_share, 1))

    victim = max(victims, key=lambda c: c.throttle_rate_pct)
    action = (
        f"In shared-throughput database '{database}' ({shared_ru:.0f} RU/s shared across "
        f"{len(active)} collections), collection '{monopolizer.name}' consumes "
        f"{mono_share:.0f}% of the pool while '{victim.name}' throttles at "
        f"{victim.throttle_rate_pct:.0f}% despite using only {shares[victim.name]:.0f}% — it is being "
        f"starved. Move '{monopolizer.name}' (or the starved '{victim.name}') to dedicated throughput, "
        f"or migrate collections off the shared pool. (The exact internal RU split per collection is "
        f"not exposed; this is inferred from the 429 + consumption disparity.)"
    )
    return verdict(
        is_starvation=True, root_cause="starvation", severity="high",
        monopolizer=monopolizer.name, monopolizer_ru_share_pct=round(mono_share, 1),
        victim=victim.name, victim_throttle_rate_pct=round(victim.throttle_rate_pct, 1),
        recommended_action=action,
    )


def detect_shared_throughput_starvation(
    la: LogAnalyticsProvider,
    account_resource_id: str,
    database: str,
    shared_ru: float,
    window: TimeWindow,
    *,
    config: SharedThroughputConfig | None = None,
    source: DataPlaneSource = DataPlaneSource.RAW,
) -> SharedThroughputVerdict:
    """Run DX-003 after the pipeline has established the required LA capability.

    An empty result means the configured table has no matching rows in this analysis window. Query
    failures remain explicit abstentions and are not relabeled as missing diagnostic settings.
    """
    span = (window.start, window.end)
    try:
        source.validate_window(window)
        rows = la.query_resource(account_resource_id, traffic_kql(database, source, window), span)
        source.validate_rows(rows, counts=("requests", "throttled"), charges=("ru",))
    except Exception as exc:  # noqa: BLE001 - preserve a failed detector as an explicit abstention
        verdict = _abstain(database, "query_error", f"Log Analytics query failed: {exc}")
        verdict.methodology.update(source.evidence(window))
        return verdict
    collections = [
        CollectionTraffic(
            name=r.get("CollectionName") or "",
            requests=int(r.get("requests") or 0),
            throttled_429=int(r.get("throttled") or 0),
            ru_consumed=float(r.get("ru") or 0.0),
        )
        for r in rows if r.get("CollectionName")
    ]
    if not collections:
        verdict = _abstain(
            database, "insufficient_data", "No data-plane telemetry in this analysis window."
        )
        verdict.methodology.update(source.evidence(window))
        return verdict
    verdict = classify(database, collections, shared_ru, config)
    verdict.methodology.update(source.evidence(window))
    return verdict

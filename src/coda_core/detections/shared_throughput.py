"""DX-003: Shared-throughput starvation.

Only containers without dedicated throughput draw from the database-level RU/s pool. A single
container can compete with its siblings for capacity. Their observed RU and 429s do not prove
the database is at its cap, or that a specific container caused another container's throttling.

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

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from math import isfinite

from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import DataPlaneSource, LogAnalyticsProvider
from coda_core.providers.shared_offer import IncompletePool, PoolMembers, verified_members

INTERVAL = timedelta(minutes=5)

# Shared-pool throttling is a present-tense signal; a 1-day window over the data-plane logs is enough.
def production_window(
    now: datetime | None = None, source: DataPlaneSource = DataPlaneSource.RAW,
) -> TimeWindow:
    """Keep the full production day, ending at a complete bucket for aggregated logs."""
    anchor = source.anchor(now or datetime.now(timezone.utc))
    return TimeWindow(anchor - timedelta(days=1), anchor, timedelta(hours=1))


def traffic_kql(
    database: str | list[str], source: DataPlaneSource = DataPlaneSource.RAW,
    window: TimeWindow | None = None,
) -> str:
    """Keep member and UTC interval identity in both direct and account-prefetched reads."""
    def literal(name):
        return "'" + name.replace("\\", "\\\\").replace("'", "\\'") + "'"

    predicate = (f"DatabaseName == {literal(database)}" if isinstance(database, str) else
                 f"DatabaseName in ({', '.join(map(literal, database))})")
    bounds = (f"| where TimeGenerated >= datetime({window.start.isoformat()}) "
              f"and TimeGenerated < datetime({window.end.isoformat()}) "
              if window and source is DataPlaneSource.RAW else "")
    return (
        source.query_table(window) + bounds
        + f"| where {predicate} and isnotempty(CollectionName) "
        f"| summarize requests = {source.count}, "
        f"throttled = {source.count_if('StatusCode == 429')}, "
        f"ru = sum({source.charge}){source.invalid_rows} by DatabaseName, CollectionName, bucket = bin(TimeGenerated, 5m)"
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
    min_requests: int = 100         # a collection below this is inactive in that five-minute interval
    pool_throttle_pct: float = 5.0  # database-wide 429 rate at/above this = pool under pressure
    dominance_pct: float = 60.0     # one collection consuming >= this share of pool RU = monopoliser
    victim_throttle_pct: float = 5.0  # a starved sibling throttles at/above this
    victim_share_pct: float = 20.0    # ...while consuming <= this share of pool RU


@dataclass(frozen=True)
class SharedThroughputVerdict:
    is_starvation: bool
    root_cause: str
    database: str
    collection_count: int
    pool_throttle_rate_pct: float
    monopolizer: str | None
    monopolizer_ru_share_pct: float
    victim: str | None
    victim_throttle_rate_pct: float
    severity: str  # high only for confirmed contention; otherwise none
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


def _interval_verdicts(
    database: str, collections: list[CollectionTraffic], shared_ru: float,
    cfg: SharedThroughputConfig,
) -> list[SharedThroughputVerdict]:
    """Evaluate one complete bin; keep all qualifying victims so rank changes cannot hide a pair."""
    active = [c for c in collections if c.requests >= cfg.min_requests]
    ru_total = sum(c.ru_consumed for c in active)
    req_total = sum(c.requests for c in active)
    thr_total = sum(c.throttled_429 for c in active)
    pool_rate = (100.0 * thr_total / req_total) if req_total else 0.0

    method = {"thresholds": asdict(cfg), "shared_ru": shared_ru, "active_collections": len(active),
              "note": "The internal RU allocation is not exposed; contention is inferred, not proven."}

    def verdict(**kw) -> SharedThroughputVerdict:
        base = dict(
            is_starvation=False, root_cause="no_disparity", database=database,
            collection_count=len(active), pool_throttle_rate_pct=round(pool_rate, 2),
            monopolizer=None, monopolizer_ru_share_pct=0.0, victim=None,
            victim_throttle_rate_pct=0.0, severity="none", recommended_action="",
            methodology=method,
        )
        base.update(kw)
        return SharedThroughputVerdict(**base)

    if len(active) < 2:
        return [verdict(root_cause="single_collection")]
    if pool_rate < cfg.pool_throttle_pct:
        return [verdict(root_cause="below_pool_throttle_threshold" if thr_total else "not_throttling")]
    if ru_total <= 0:
        return [verdict(root_cause="insufficient_data")]

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
        return [verdict(root_cause="no_disparity",
                        monopolizer=monopolizer.name, monopolizer_ru_share_pct=round(mono_share, 1))]

    return [verdict(
        root_cause="possible_contention",
        monopolizer=monopolizer.name, monopolizer_ru_share_pct=round(mono_share, 1),
        victim=victim.name, victim_throttle_rate_pct=round(victim.throttle_rate_pct, 1),
        methodology={**method, "affected_ru_share_pct": round(shares[victim.name], 1),
                     "interval_requests": req_total, "interval_429s": thr_total,
                     "affected_requests": victim.requests, "affected_429s": victim.throttled_429},
    ) for victim in sorted(victims, key=lambda c: (-c.throttle_rate_pct, c.name))]


def classify(database: str, buckets: dict[datetime, dict[str, CollectionTraffic]], shared_ru: float,
             window: TimeWindow, members: set[str], config: SharedThroughputConfig | None = None) -> SharedThroughputVerdict:
    """Confirm only an identical ordered pair in adjacent completed, independently qualifying bins."""
    cfg = config or SharedThroughputConfig()
    previous = {}
    previous_stamp = None
    possible = confirmed = last = None
    incomplete = 0
    totals: dict[str, list[int]] = {}
    for stamp, rows in sorted(buckets.items()):
        for name, row in rows.items():
            counts = totals.setdefault(name, [0, 0])
            counts[0] += row.requests
            counts[1] += row.throttled_429
        if stamp < window.start or stamp + INTERVAL > window.end or rows.keys() != members:
            incomplete += 1
            previous = {}
            continue
        verdicts = _interval_verdicts(database, list(rows.values()), shared_ru, cfg)
        last = verdicts[0]
        if last.root_cause == "insufficient_data":
            incomplete += 1
        pairs = {(v.monopolizer, v.victim): v for v in verdicts if v.root_cause == "possible_contention"}
        if pairs:
            possible = (stamp, last)
            if previous_stamp == stamp - INTERVAL:
                match = next((p for p in pairs if p in previous), None)
                if match is not None:
                    confirmed = [(previous_stamp, previous[match]), (stamp, pairs[match])]
        previous_stamp, previous = stamp, pairs

    observed = {"observed_requests": sum(c[0] for c in totals.values()),
                "observed_429s": sum(c[1] for c in totals.values()),
                "member_observations": [{"container": name, "requests": counts[0], "throttled": counts[1]}
                                        for name, counts in sorted(totals.items())],
                "incomplete_or_partial_intervals": incomplete}
    if possible:
        witnesses = confirmed or [possible]
        v = witnesses[-1][1]
        observed.update(dominant_container=v.monopolizer, affected_container=v.victim, intervals=[
            {"start": stamp.isoformat(), "end": (stamp+INTERVAL).isoformat(),
             "pool_throttle_pct": w.pool_throttle_rate_pct, "dominant_ru_share_pct": w.monopolizer_ru_share_pct,
             "affected_throttle_pct": w.victim_throttle_rate_pct,
             **{k: w.methodology[k] for k in ("affected_ru_share_pct", "interval_requests", "interval_429s",
                                             "affected_requests", "affected_429s")}} for stamp, w in witnesses])
        if confirmed:
            v = replace(v, is_starvation=True, root_cause="starvation", severity="high", recommended_action=(
                f"Investigate '{v.monopolizer}' and '{v.victim}' during the reported intervals. "
                "Check whether pacing or rescheduling the competing work relieves throttling. "
                "If the workloads must run together and require isolation, evaluate dedicated throughput. "
                "These logs do not establish the internal allocation or prove which workload caused a 429."))
    elif incomplete or last is None:
        v = _abstain(database, "insufficient_data", "Shared-member traffic is incomplete for interval comparison")
    else:
        v = last
        if v.root_cause == "not_throttling" and observed["observed_429s"]:
            v = replace(v, root_cause="throttling_without_confirmed_contention")
    missing = sorted(members - totals.keys())
    return replace(v, methodology={**v.methodology, **observed, "missing_members": missing,
                                   "expected_members": len(members), "observed_members": len(totals)})


def detect_shared_throughput_starvation(
    la: LogAnalyticsProvider,
    account_resource_id: str,
    database: str,
    shared_ru: float,
    window: TimeWindow,
    *,
    config: SharedThroughputConfig | None = None,
    source: DataPlaneSource = DataPlaneSource.RAW,
    pool_members: PoolMembers | None = None,
    as_of: datetime | None = None,
) -> SharedThroughputVerdict:
    """Run DX-003 after the pipeline has established the required LA capability.

    An empty result means the configured table has no matching rows in this analysis window. Query
    failures remain explicit abstentions and are not relabeled as missing diagnostic settings.
    """
    span = (window.start, window.end)
    try:
        members = set(verified_members(pool_members))
    except IncompletePool as exc:
        return _abstain(database, "insufficient_data", str(exc))
    try:
        source.validate_window(window)
        rows = la.query_resource(account_resource_id, traffic_kql(database, source, window), span)
        rows = [row for row in rows if row.get("CollectionName") in members]
        source.validate_rows(rows, counts=("requests", "throttled"), charges=("ru",))
    except Exception as exc:  # noqa: BLE001 - preserve a failed detector as an explicit abstention
        verdict = _abstain(database, "query_error", f"Log Analytics query failed: {exc}")
        verdict.methodology.update(source.evidence(window))
        return verdict
    buckets: dict[datetime, dict[str, CollectionTraffic]] = {}
    end = min(window.end, as_of or datetime.now(timezone.utc))
    for r in rows:
        stamp, name = r.get("bucket"), r["CollectionName"]
        if (not isinstance(stamp, datetime) or stamp.utcoffset() is None or stamp.timestamp() % 300
                or not window.start-INTERVAL < stamp < end or name in buckets.get(stamp, {})
                or any(not isinstance(r.get(k), (int, float)) or isinstance(r[k], bool)
                       or not isfinite(r[k]) or r[k] < 0 for k in ("requests", "throttled", "ru"))
                or any(int(r[k]) != r[k] for k in ("requests", "throttled"))
                or r["throttled"] > r["requests"]):
            verdict = _abstain(database, "insufficient_data", "Invalid or ambiguous shared-member interval")
            verdict.methodology.update(source.evidence(window))
            return verdict
        buckets.setdefault(stamp.astimezone(timezone.utc), {})[name] = CollectionTraffic(
            name, int(r["requests"]), int(r["throttled"]), r["ru"])
    if end <= window.start:
        return _abstain(database, "insufficient_data", "No elapsed observation window")
    verdict = classify(database, buckets, shared_ru, TimeWindow(window.start, end, INTERVAL), members, config)
    verdict.methodology.update(source.evidence(window))
    return verdict

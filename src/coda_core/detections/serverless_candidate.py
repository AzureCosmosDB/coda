"""DX-014: compare like-for-like throughput costs only after verifying account eligibility."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from math import isfinite

from coda_core.providers.arm import AccountConfig, ThroughputOffer
from coda_core.providers.base import DataProvider, TimeWindow
from coda_core.providers.cost_management import CostManagementProvider

PRODUCTION_WINDOW_DAYS = 30
HOUR = timedelta(hours=1)


@dataclass(frozen=True)
class ServerlessCandidateConfig:
    """A comparison needs all hours in the last 30 completed UTC billing dates."""

    required_hours: int = PRODUCTION_WINDOW_DAYS * 24


def _midnight(stamp: datetime) -> datetime:
    return stamp.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def production_window(now: datetime | None = None) -> TimeWindow:
    """Include today's observations, but do not compare a partial UTC billing date."""
    end = now or datetime.now(timezone.utc)
    return TimeWindow(_midnight(end) - timedelta(days=PRODUCTION_WINDOW_DAYS), end, HOUR)


def eligibility(config: AccountConfig, offers: tuple[ThroughputOffer, ...],
                inventory_issues: tuple[str, ...]) -> tuple[str, str]:
    """Known blockers take precedence over missing evidence. Unclassified features are not blockers."""
    names = {n.casefold().replace(" ", "") for n in config.location_names if n and n.strip()}
    replicas = {n.casefold().replace(" ", "") for n in config.reported_replica_regions if n.strip()}
    if config.is_serverless or any(c.casefold() == "enableserverless" for c in config.capabilities):
        return "not_applicable", "account is already serverless"
    if config.region_count > 1 or config.write_region_count > 1 or len(names | replicas) > 1:
        return "not_applicable", "multiple configured regions (including read replicas)"
    if any(o.level == "database" for o in offers):
        return "not_applicable", "shared database throughput"
    if config.free_tier is True:
        return "not_applicable", "free tier is enabled"
    if config.priority_based_execution is True:
        return "not_applicable", "priority-based execution is enabled"
    if config.burst_capacity is True:
        return "not_applicable", "provisioned burst capacity is enabled"
    if (config.write_region_count != 1 or config.region_count != 1 or len(names) != 1
            or any(not n.strip() for n in config.reported_replica_regions)):
        return "eligibility_unverified", "region configuration is incomplete"
    if (inventory_issues or not offers or any(o.level != "container" or o.mode not in {"manual", "autoscale"}
                                              for o in offers)):
        return "eligibility_unverified", "dedicated provisioned offer inventory is unverified"
    if config.api != "sql" or config.api_kind.casefold() != "globaldocumentdb":
        return "eligibility_unverified", "this ARM inventory verifies only NoSQL databases and containers"
    missing = [label for value, label in ((config.free_tier, "free-tier setting"),
               (config.priority_based_execution, "priority-based execution setting"),
               (config.burst_capacity, "burst capacity setting"),
               (config.multi_region_writes_enabled, "single-write setting")) if value is not False]
    if not config.capability_inventory_complete:
        missing.append("capability inventory")
    if config.capabilities:
        missing.append("compatibility of configured capabilities")
    if missing:
        return "eligibility_unverified", "unverified: " + ", ".join(missing)
    return "compatible", "single-region provisioned NoSQL; verified dedicated offers and feature checks"


@dataclass(frozen=True)
class ServerlessCandidateVerdict:
    """Keep preflight, actual measurements and price provenance explicit and distinct."""

    root_cause: str
    summary: str
    recommended_action: str
    methodology: dict


def detect_serverless_candidate(metrics: DataProvider, rid: str, window: TimeWindow, *,
                               account: AccountConfig, offers: tuple[ThroughputOffer, ...],
                               inventory_issues: tuple[str, ...], cost: CostManagementProvider | None
                               ) -> ServerlessCandidateVerdict:
    """Read consumption only for compatible accounts, and pricing only for a complete measured month."""
    state, reason = eligibility(account, offers, inventory_issues)
    evidence = {"eligibility": state, "eligibility_reason": reason}

    def verdict(cause, summary, action=""):
        return ServerlessCandidateVerdict(cause, summary, action, {**evidence, "root_cause": cause})

    if state != "compatible":
        evidence["visible_observation"] = True
        return verdict(state, f"DX-014 {state.replace('_', ' ')}: {reason}.")
    series = metrics.get_metric(rid, "TotalRequestUnits", TimeWindow(window.start, window.end, HOUR),
                                aggregation="Total")
    hours = {}
    for p in series.points:
        if not window.start <= p.timestamp < window.end:
            continue
        n = p.value
        hours[p.timestamp] = (Decimal(str(n)) if p.timestamp not in hours and type(n) in (float, int)
                              and isfinite(n) and n >= 0 else None)
    # A clock label amid finer-grained samples is not an hourly total. Never double count
    # overlapping samples or silently price just the bucket at the top of each hour.
    off_grid_hours = {s.replace(minute=0, second=0, microsecond=0) for s in hours
                      if s.minute or s.second or s.microsecond}
    measured = {s: v for s, v in hours.items() if v is not None and
                s.replace(minute=0, second=0, microsecond=0) not in off_grid_hours}
    end = _midnight(window.end)
    start = end - timedelta(days=PRODUCTION_WINDOW_DAYS)
    required = ServerlessCandidateConfig().required_hours
    stamps = [start + i*HOUR for i in range(required)]
    covered = sum(stamp in measured for stamp in stamps)
    evidence.update(measured_buckets=len(measured), comparison_hours=covered,
                    comparison_start=start.isoformat(), comparison_end=end.isoformat())
    if not measured:
        return verdict("insufficient_data", "No usable account-total consumed-RU measurements.")
    observed = sum(measured.values())
    evidence.update(visible_observation=True, observed_ru=float(observed),
                    observation_start=window.start.isoformat(), observation_end=window.end.isoformat())
    summary = f"Observed {observed:,.2f} RU across {len(measured):,} measured account buckets."
    if covered != required or window.start > start:
        return verdict("incomplete_history", f"{summary} {covered} of {required} completed comparison hours measured.")
    if cost is None or account.zone_redundant_region_count != 0:
        return verdict("pricing_unavailable", f"{summary} No verified comparable throughput prices.")
    region = account.location_names[0]
    try:
        days = cost.serverless_comparison_days(start.date(), end.date(), resource_id=rid, region=region)
        if set(days) != {s.date() for s in stamps}:
            raise ValueError("Incomplete billing dates")
        currencies = {v.currency for v in days.values()}
        if (len(currencies) != 1 or not all(v.provisioned_cost.is_finite() and v.provisioned_cost >= 0
                and v.price_per_million_ru.is_finite() and v.price_per_million_ru > 0 for v in days.values())):
            raise ValueError("Incomparable pricing")
        currency = currencies.pop()
        provisioned = sum(v.provisioned_cost for v in days.values())
        daily_ru = defaultdict(Decimal)
        for s in stamps:
            daily_ru[s.date()] += measured[s]
        alternative = sum(ru * days[d].price_per_million_ru for d, ru in daily_ru.items()) / 1_000_000
    except Exception as exc:  # noqa: BLE001 - optional billing cannot erase measured consumption
        evidence["price_issue"] = type(exc).__name__
        return verdict("pricing_unavailable", f"{summary} Comparable daily throughput pricing was unavailable.")
    evidence.update(consumed_ru=float(sum(measured[s] for s in stamps)), currency=currency,
                    provisioned_cost=float(provisioned), estimated_serverless_cost=float(alternative),
                    price_source="customer_amortized_bill", serverless_rate_scope="subscription_region",
                    region=region, serverless_meter="1M RUs", provisioned_meter="100 RU/s",
                    daily_comparison=[{"date": d.isoformat(), "consumed_ru": float(ru),
                                       "provisioned_cost": float(days[d].provisioned_cost),
                                       "price_per_million_ru": float(days[d].price_per_million_ru)}
                                      for d, ru in daily_ru.items()])
    comparison = (f"For {start.date()} to {end.date()} (end exclusive), measured "
                  f"{evidence['consumed_ru']:,.2f} RU: estimated serverless {currency} {alternative:,.2f} "
                  f"at this subscription's regional meter rates versus actual provisioned throughput "
                  f"{currency} {provisioned:,.2f}.")
    if alternative >= provisioned:
        return verdict("not_cheaper", f"{comparison} No lower serverless throughput cost.")
    return verdict("serverless_candidate", comparison, "Evaluate serverless for this workload; "
                   "confirm partition burst capacity, application fit and actual terms. "
                   "A lower historical throughput estimate is not a forecast.")

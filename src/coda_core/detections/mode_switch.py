"""Compare manual and autoscale throughput for the same capacity and measured hours (ADR-0086)."""

from dataclasses import dataclass
from datetime import datetime
from math import fsum, isclose

from azure.core.exceptions import AzureError

from coda_core.detections.autoscale_signal import autoscaled_utilization_series
from coda_core.detections.throughput_history import HOUR, MONTH, WEEK, throughput_history
from coda_core.framework.cost_rate import MULTI_WRITE_METER, regional_mode_units, throughput_meter
from coda_core.providers.arm import AccountConfig
from coda_core.providers.base import MetricPoint, MetricSeries, TimeWindow

EMPTY = MetricSeries("Throughput", "Maximum", "Percent", ())


def _offer_meter(account):
    """Do not price only a subset of a topology if ARM also reports another replica region."""
    meter = throughput_meter(account)
    if meter and {r.casefold() for r in account.reported_replica_regions} <= {
            r.casefold() for r in account.location_names}:
        return meter
    return None


@dataclass(frozen=True)
class ModeSwitchVerdict:
    """Keep pricing-mode observations distinct from recommendations and currency estimates."""

    recommend_switch: bool
    root_cause: str
    severity: str
    summary: str
    recommended_action: str
    methodology: dict


def assess_mode(current: str, series: MetricSeries, capacity: float, window: TimeWindow,
                account: AccountConfig | None, created_at: datetime | None = None,
                existed_by: datetime | None = None, *, regional: dict[str, MetricSeries] | None = None,
                read_issues: dict[str, str] | None = None) -> ModeSwitchVerdict:
    """Price both modes in units of their common throughput meter; its unit price cancels.

    DX-012 models autoscale from each hourly normalized peak. DX-013 uses the actual highest
    scaled throughput in each hour. Neither direction resizes capacity or extrapolates dollars.
    """
    def history(data):
        """Validate each region independently against the same closed-hour anchor."""
        return throughput_history(data, window, created_at, existed_by=existed_by,
                                  exclude_unverified_zero_padding=current == "manual")

    aggregate = history(series)
    histories = ({r: history(regional.get(r, EMPTY)) for r in account.location_names}
                 if regional is not None and account else {})
    consecutive = min((h.consecutive for h in histories.values()), default=aggregate.consecutive)
    size = MONTH if consecutive == MONTH else WEEK if consecutive >= WEEK else 0
    inputs = {r: (h.evaluated.values()[-size:] if size else h.observed.values()) for r, h in histories.items()}
    regional_values = [v for region_values in inputs.values() for v in region_values]
    values = regional_values or aggregate.evaluated.values()
    evidence = aggregate.evidence() if not histories else {
        "observed_samples": (sum(len(h.observed.points) for h in histories.values()) if regional_values
                             else len(aggregate.observed.points)),
        "evaluated_samples": len(values), "latest_consecutive_hours": consecutive,
        "observation_scope": "regional_readings" if regional_values else "offer_aggregate_only",
        "coverage_end_exclusive": aggregate.end.isoformat(),
        "regional_measured_hours": {r: h.consecutive for r, h in histories.items()},
        "regional_read_issues": read_issues or {},
    }
    if not values:
        detail = ("No usable manual utilization measurements." if current == "manual" else
                  "No usable complete hourly scaled-throughput totals.")
        if histories:
            detail += " Region-resolved hourly evidence is unavailable."
        return ModeSwitchVerdict(False, "no_data", "none", detail,
                                 "", {**evidence, "abstained": "no_data"})
    avg, peak = fsum(values) / len(values), max(values)
    label = "actual scaled throughput"
    if current == "manual":
        label = "hourly peak utilization" if window.granularity == HOUR else "normalized utilization"
    if histories and any(inputs.values()):
        label = "regional " + label
    summary = (f"Observed {label}: average {avg:.1f}%, peak {peak:.1f}% of {capacity:g} RU/s "
               f"over {len(values)} samples; {consecutive} consecutive completed hours"
               f"{' across all configured regions' if histories else ''}.")
    if current == "autoscale":
        peak_ru = peak / 100 * capacity
        summary += f" Highest observed scaled throughput: {peak_ru:g} RU/s."
        evidence.update(peak_scaled_ru=peak_ru, average_scaled_ru=avg / 100 * capacity)
    meter = _offer_meter(account)
    if meter == MULTI_WRITE_METER:
        summary += " The multi-write meter has the same per-unit price for manual and autoscale."
    if any(h.unverified_leading_zeros for h in (histories.values() if histories else (aggregate,))):
        summary += " Leading zero readings without resource-existence evidence do not establish history."
    evidence.update(average_pct=avg, peak_pct=peak, configured_capacity_ru=capacity, advice_stage="observation")

    def observation(reason: str, detail: str = "") -> ModeSwitchVerdict:
        """A missing economic comparison never hides the measured signal."""
        return ModeSwitchVerdict(False, reason, "none", summary + detail, "", evidence)

    if consecutive < WEEK:
        return observation("incomplete_week", " Regional evidence is incomplete." if histories else "")
    if (not meter or capacity < 1000 or capacity % 1000 != 0
            or account.region_count > 1 and account.is_pppra_enabled is None):
        return observation("comparison_unavailable", " An equal-capacity comparison is unavailable "
                           "for this topology or setting.")
    factors = regional_mode_units(account, meter, capacity)
    if not factors:
        return observation("comparison_unavailable", " Regional billing factors are unverified.")
    if not inputs:
        if account.region_count > 1 and (current != "manual" or account.is_pppra_enabled is not False):
            return observation("comparison_unavailable", " Region-resolved hourly measurements are required.")
        # Only traditional autoscale applies the modeled busiest partition/region to all regions.
        inputs = dict.fromkeys(account.location_names, values)
    elif current == "manual" and account.is_pppra_enabled is False:
        # If the global scalar was not usable, its exact equivalent is the per-hour maximum
        # across all independently verified regions, not the average of their monthly peaks.
        hottest = [max(hour) for hour in zip(*inputs.values(), strict=True)]
        inputs = dict.fromkeys(account.location_names, hottest)
    rows = {}
    for r, (manual_full, auto_full) in factors.items():
        rows[r] = {"manual_units": manual_full * size,
                   "autoscale_units": auto_full * fsum(max(10.0, pct) / 100 for pct in inputs[r])}
    evidence.update(meter=meter, equal_capacity_ru=capacity, regional_meter_units=rows,
                    manual_meter_units=fsum(row["manual_units"] for row in rows.values()),
                    autoscale_meter_units=fsum(row["autoscale_units"] for row in rows.values()),
                    autoscale_input=("actual_scaled" if current == "autoscale" else
                                     "regional_hourly_peak_upper_bound" if account.is_pppra_enabled is True
                                     else "modeled_from_hourly_peak"),
                    throughput_metric=("NormalizedRUConsumption" if current == "manual" else
                                       "ProvisionedThroughput" if account.is_pppra_enabled is False else "AutoscaledRU"),
                    zone_premium_regions=(0 if account.multi_region_writes_enabled else account.zone_redundant_region_count),
                    scaling_basis=("traditional" if account.is_pppra_enabled is False else
                                   "dynamic" if account.is_pppra_enabled is True else "single_region"))
    alternate = "autoscale" if current == "manual" else "manual"
    # A regional price cancels only within that region. A blended account rate must not settle
    # opposite regional deltas. Ties in one region do not erase a strict improvement elsewhere.
    pairs = [(row[current + "_units"], row[alternate + "_units"]) for row in rows.values()]
    if any(a > b for a, b in pairs) and any(a < b for a, b in pairs):
        return observation("regional_prices_required", " Regional estimates favor different modes; "
                           "region-specific unit prices are required to identify the cheaper total.")
    if not any(a > b and not isclose(a, b, rel_tol=1e-12) for a, b in pairs):
        evidence["advice_stage"] = "no_change"
        note = (" The regional peak model does not establish that autoscale is cheaper; independent "
                "partition scaling could use less." if current == "manual" and account.is_pppra_enabled is True
                else f" {alternate.capitalize()} was not cheaper in the equal-capacity estimate.")
        return observation("not_cheaper", note)
    comparison = f" At equal capacity, {alternate} has the lower estimated throughput cost for those hours."
    if consecutive < MONTH:
        evidence["advice_stage"] = "review"
        return ModeSwitchVerdict(False, "review", "none", summary + comparison,
                                 "Review whether this measured week is representative.", evidence)
    evidence["advice_stage"] = "recommendation"
    return ModeSwitchVerdict(True, "lower_estimated_cost", "medium", summary + comparison,
                             f"Consider switching to {alternate} at the same {capacity:g} RU/s capacity. "
                             "Check service limits, billing terms and expected future load first; "
                             "future savings are not guaranteed.", evidence)


def _regional_reads(account, reader):
    """Keep good regions as observations; a missing/denied/ambiguous region cannot be prorated."""
    data, issues = {}, {}
    for r in account.location_names:
        try:
            data[r] = reader(r)
        except (AzureError, ValueError) as exc:
            issues[r] = type(exc).__name__
    return data, issues


def _observation_fallback(data, issues, reader):
    """Use an available aggregate only to describe a signal, never to fill an absent region."""
    if issues or any(s.points for s in data.values()):
        return EMPTY
    try:
        return reader()
    except (AzureError, ValueError) as exc:
        issues["aggregate"] = type(exc).__name__
        return EMPTY


def detect_manual_to_autoscale(provider, account_resource_id: str, database: str, container: str,
                             provisioned_ru: float, window: TimeWindow, *,
                             account: AccountConfig | None = None,
                             resource_created_at: datetime | None = None,
                             resource_existed_by: datetime | None = None) -> ModeSwitchVerdict:
    """Evaluate one dedicated manual offer without inferring an autoscale ceiling from peaks."""
    def normalized(region=None):
        """A multi-region global maximum is usable as a common projection only for traditional scaling."""
        scope = {"DatabaseName": database, "CollectionName": container}
        if region is not None:
            scope["Region"] = region
        strict = {"require_single_series": True} if region or (account and account.region_count > 1) else {}
        return provider.get_metric(account_resource_id, "NormalizedRUConsumption", window, aggregation="Maximum",
                                   dimension_filter=scope, **strict)

    regional = issues = None
    meter = _offer_meter(account)
    if meter and account.is_pppra_enabled is True:
        regional, issues = _regional_reads(account, normalized)
        data = _observation_fallback(regional, issues, normalized)
    elif meter and account.region_count > 1 and account.is_pppra_enabled is False:
        try:
            data = normalized()
        except ValueError:
            data = EMPTY  # An unaggregated regional slice is not the common hottest-hour signal.
        if not data.points:
            regional, issues = _regional_reads(account, normalized)
    else:
        data = normalized()
    return assess_mode("manual", data, provisioned_ru, window, account, resource_created_at, resource_existed_by,
                       regional=regional, read_issues=issues)


def detect_autoscale_to_manual(provider, account_resource_id: str, database: str, container: str,
                             provisioned_ru: float, window: TimeWindow, *,
                             account: AccountConfig | None = None,
                             resource_created_at: datetime | None = None) -> ModeSwitchVerdict:
    """Evaluate one dedicated autoscale offer using measured scaled throughput, not consumption."""
    def measured(region=None):
        """Read a certified actual throughput history, not demand or an ARM ceiling."""
        if account and account.is_pppra_enabled is False:
            # AutoscaledRU is a dynamic-scaling metric. The regional ProvisionedThroughput hourly
            # maximum is the historical scaled/billed signal, not the configured maximum (from ARM).
            scope = {"DatabaseName": database, "CollectionName": container}
            if region is not None:
                scope["Region"] = region
            ru = provider.get_metric(account_resource_id, "ProvisionedThroughput", window, aggregation="Maximum",
                                     dimension_filter=scope, require_single_series=True)
            return MetricSeries(ru.name, "Maximum", "Percent", tuple(
                MetricPoint(p.timestamp, 100*p.value/provisioned_ru if p.value is not None and
                            provisioned_ru > 0 and p.value >= 0.1*provisioned_ru else None) for p in ru.points))
        return autoscaled_utilization_series(provider, account_resource_id, database, container,
                                             provisioned_ru, window, region=region)

    regional = issues = None
    if _offer_meter(account) and account.is_pppra_enabled is not None:
        regional, issues = _regional_reads(account, measured)
        data = _observation_fallback(regional, issues, measured)
    else:
        data = measured()
    return assess_mode("autoscale", data, provisioned_ru, window, account, resource_created_at,
                       regional=regional, read_issues=issues)

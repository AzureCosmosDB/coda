"""DX-012 / DX-013: throughput **mode-switch** recommendations (manual ↔ autoscale).

Part of the throughput right-sizing family (docs/detections/throughput-right-sizing-family.md). These
two share DX-001's utilization signal (``NormalizedRUConsumption``) but read a different shape of it —
the **duty cycle** (how spiky vs steady the workload is) — and recommend a **mode change**, not a
capacity change:

* **DX-012 manual → autoscale.** A *manual* container whose load is **spiky** (high peak utilisation
  but a low average — it sits mostly idle and occasionally spikes). Manual bills the fixed RU/s 24/7,
  so a spiky workload wastes the idle time; autoscale's 10% floor cuts that. This is distinct from
  DX-001, which fires on *steady-low* utilisation (low p99) — DX-012 needs a **high** p99 (the peaks
  are real, so right-sizing down would cause throttling) with a **low** average.
* **DX-013 autoscale → manual.** An *autoscale* container whose load is **steady-high** (average
  sustained near the max, with little spikiness). Autoscale carries a per-RU premium over manual, so a
  workload that stays high doesn't benefit from scaling and would be cheaper on manual at a fixed RU/s.

Per ADR-0012 these are **qualitative** recommendations — a mode switch is a pricing optimisation, not
a capacity (RU/s) recovery, so no RU/s waste figure is asserted. Read-only / diagnose-only.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime

from coda_core.detections.over_provisioning import (
    DATA_REQUIREMENT,
    UtilizationStats,
    utilization_stats,
)
from coda_core.providers.base import DataProvider, TimeWindow
from coda_core.sufficiency import evaluate_age, evaluate_series


@dataclass(frozen=True)
class DutyCycleSignal:
    """How spiky vs steady a container's utilisation is, over the window."""

    avg: float            # average utilisation (% of provisioned)
    p99: float            # p99 utilisation (% of provisioned)
    max_util: float       # peak utilisation (% of provisioned)
    peak_to_avg: float    # max / avg — high = spiky, ~1 = flat/steady
    sample_count: int

    @classmethod
    def from_stats(cls, s: UtilizationStats) -> DutyCycleSignal:
        ratio = (s.max / s.avg) if s.avg > 0 else 0.0
        return cls(avg=s.avg, p99=s.p99, max_util=s.max, peak_to_avg=ratio,
                   sample_count=s.sample_count)


@dataclass(frozen=True)
class ModeSwitchConfig:
    """Thresholds for the duty-cycle triggers (autoscale economics, ADR-0012 / family doc)."""

    # DX-012 manual -> autoscale: a real peak (high max) but mostly idle (low avg) = bursty. Manual
    # must provision for the peak 24/7; autoscale serves it on demand and floors at 10% when idle.
    spiky_peak_floor: float = 40.0    # peak must reach this — the spike is genuine, not noise
    spiky_avg_ceiling: float = 30.0   # average below this — mostly idle between spikes
    spiky_ratio: float = 5.0          # peak-to-average (burst) ratio at/above this = bursty
    # DX-013 autoscale -> manual: average sustained high, not spiky = steady-high.
    steady_avg_floor: float = 66.0    # average at/above ~2/3 of max
    steady_ratio_ceiling: float = 1.3  # peak barely above average = flat/steady


@dataclass(frozen=True)
class ModeSwitchVerdict:
    recommend_switch: bool
    # spiky_manual | steady_autoscale | well_matched | insufficient_data
    root_cause: str
    current_mode: str          # manual | autoscale
    recommended_mode: str      # autoscale | manual | (same)
    avg: float
    p99: float
    max_util: float
    peak_to_avg: float
    severity: str              # medium | low | none
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def classify_manual_to_autoscale(
    signal: DutyCycleSignal, provisioned_ru: float, config: ModeSwitchConfig | None = None
) -> ModeSwitchVerdict:
    """DX-012: a bursty *manual* container is a candidate to convert to autoscale."""
    cfg = config or ModeSwitchConfig()
    method = {"avg": round(signal.avg, 1), "max": round(signal.max_util, 1),
              "peak_to_avg": round(signal.peak_to_avg, 2),
              "thresholds": {"spiky_peak_floor": cfg.spiky_peak_floor,
                             "spiky_avg_ceiling": cfg.spiky_avg_ceiling,
                             "spiky_ratio": cfg.spiky_ratio}}

    def verdict(**kw) -> ModeSwitchVerdict:
        base = dict(recommend_switch=False, root_cause="well_matched", current_mode="manual",
                    recommended_mode="manual", avg=round(signal.avg, 1), p99=round(signal.p99, 1),
                    max_util=round(signal.max_util, 1), peak_to_avg=round(signal.peak_to_avg, 2),
                    severity="none", recommended_action="", methodology=method)
        base.update(kw)
        return ModeSwitchVerdict(**base)

    if signal.sample_count == 0:
        return verdict(root_cause="insufficient_data")
    spiky = (signal.max_util >= cfg.spiky_peak_floor
             and signal.avg <= cfg.spiky_avg_ceiling
             and signal.peak_to_avg >= cfg.spiky_ratio)
    if not spiky:
        return verdict(root_cause="well_matched")
    # Autoscale max must be >= 1000 RU/s and a multiple of 1000; size it to cover the observed peak
    # with headroom. The idle floor (10% of max) replaces the fixed manual RU/s when idle.
    peak_ru = signal.max_util / 100.0 * provisioned_ru
    target_max = max(1000.0, math.ceil(peak_ru * 1.3 / 1000.0) * 1000.0)
    return verdict(
        recommend_switch=True, root_cause="spiky_manual", recommended_mode="autoscale",
        severity="medium",
        recommended_action=(
            f"Load is bursty on this manual container (peak {signal.max_util:.0f}% vs average "
            f"{signal.avg:.0f}% of {provisioned_ru:.0f} RU/s — a {signal.peak_to_avg:.0f}x "
            f"peak-to-average ratio). Manual bills the fixed RU/s 24/7 even though the workload is "
            f"mostly idle between spikes. Convert to autoscale (max ≈ {target_max:.0f} RU/s, the "
            f"smallest that covers the peak); autoscale's 10% floor cuts idle-time cost while still "
            f"covering the peaks."
        ),
    )


def classify_autoscale_to_manual(
    signal: DutyCycleSignal, provisioned_ru: float, config: ModeSwitchConfig | None = None
) -> ModeSwitchVerdict:
    """DX-013: a steady-high *autoscale* container is a candidate to convert to manual."""
    cfg = config or ModeSwitchConfig()
    method = {"avg": round(signal.avg, 1), "max": round(signal.max_util, 1),
              "peak_to_avg": round(signal.peak_to_avg, 2),
              "thresholds": {"steady_avg_floor": cfg.steady_avg_floor,
                             "steady_ratio_ceiling": cfg.steady_ratio_ceiling}}

    def verdict(**kw) -> ModeSwitchVerdict:
        base = dict(recommend_switch=False, root_cause="well_matched", current_mode="autoscale",
                    recommended_mode="autoscale", avg=round(signal.avg, 1), p99=round(signal.p99, 1),
                    max_util=round(signal.max_util, 1), peak_to_avg=round(signal.peak_to_avg, 2),
                    severity="none", recommended_action="", methodology=method)
        base.update(kw)
        return ModeSwitchVerdict(**base)

    if signal.sample_count == 0:
        return verdict(root_cause="insufficient_data")
    steady = (signal.avg >= cfg.steady_avg_floor
              and signal.peak_to_avg <= cfg.steady_ratio_ceiling)
    if not steady:
        return verdict(root_cause="well_matched")
    return verdict(
        recommend_switch=True, root_cause="steady_autoscale", recommended_mode="manual",
        severity="medium",
        recommended_action=(
            f"Load is steady and high on this autoscale container (average {signal.avg:.0f}% of the "
            f"{provisioned_ru:.0f} RU/s max, peak {signal.max_util:.0f}% — little spikiness). "
            f"Autoscale carries a per-RU premium over manual, and a workload that stays high doesn't "
            f"benefit from scaling. Convert to manual at a fixed RU/s near the sustained level."
        ),
    )


def _series_or_abstain(provider, account_resource_id, database, container, window):
    series = provider.get_metric(
        account_resource_id, "NormalizedRUConsumption", window, aggregation="Maximum",
        dimension_filter={"DatabaseName": database, "CollectionName": container},
    )
    insuff = evaluate_series(series, DATA_REQUIREMENT)
    return series, insuff


def detect_manual_to_autoscale(
    provider: DataProvider, account_resource_id: str, database: str, container: str,
    provisioned_ru: float, window: TimeWindow, *,
    config: ModeSwitchConfig | None = None, resource_created_at: datetime | None = None,
) -> ModeSwitchVerdict:
    """End-to-end DX-012 for one manual container."""
    if resource_created_at is not None:
        age = evaluate_age(resource_created_at, window.end, DATA_REQUIREMENT.window_floor)
        if age is not None:
            return _abstain_mode("manual", "autoscale", age.reason, age.detail)
    series, insuff = _series_or_abstain(provider, account_resource_id, database, container, window)
    if insuff is not None:
        return _abstain_mode("manual", "autoscale", insuff.reason, insuff.detail)
    signal = DutyCycleSignal.from_stats(utilization_stats(series))
    return classify_manual_to_autoscale(signal, provisioned_ru, config)


def detect_autoscale_to_manual(
    provider: DataProvider, account_resource_id: str, database: str, container: str,
    provisioned_ru: float, window: TimeWindow, *,
    config: ModeSwitchConfig | None = None, resource_created_at: datetime | None = None,
) -> ModeSwitchVerdict:
    """End-to-end DX-013 for one autoscale container.

    Uses the **AutoscaledRU**-as-%-of-configured-max series (not NormalizedRUConsumption, which for
    autoscale measures against the currently-scaled value) so "steady-high" means autoscale sat near
    the configured max with little spikiness.
    """
    from coda_core.detections.autoscale_signal import autoscaled_utilization_series

    if resource_created_at is not None:
        age = evaluate_age(resource_created_at, window.end, DATA_REQUIREMENT.window_floor)
        if age is not None:
            return _abstain_mode("autoscale", "manual", age.reason, age.detail)
    series = autoscaled_utilization_series(
        provider, account_resource_id, database, container, provisioned_ru, window
    )
    insuff = evaluate_series(series, DATA_REQUIREMENT)
    if insuff is not None:
        return _abstain_mode("autoscale", "manual", insuff.reason, insuff.detail)
    signal = DutyCycleSignal.from_stats(utilization_stats(series))
    return classify_autoscale_to_manual(signal, provisioned_ru, config)


def _abstain_mode(current: str, recommended: str, reason: str, detail: str) -> ModeSwitchVerdict:
    return ModeSwitchVerdict(
        recommend_switch=False, root_cause="insufficient_data", current_mode=current,
        recommended_mode=recommended, avg=0.0, p99=0.0, max_util=0.0, peak_to_avg=0.0,
        severity="none", recommended_action="", methodology={"abstained": reason, "detail": detail},
    )


# Re-export so callers don't reach into over_provisioning for the shared helpers.
__all__ = [
    "DutyCycleSignal", "ModeSwitchConfig", "ModeSwitchVerdict",
    "classify_manual_to_autoscale", "classify_autoscale_to_manual",
    "detect_manual_to_autoscale", "detect_autoscale_to_manual",
]

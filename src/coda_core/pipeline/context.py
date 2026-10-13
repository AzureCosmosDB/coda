"""Per-unit detection context + the run-mode policy.

Carries everything an adapter needs to run one detection against one unit, and centralises the
**production vs eval** policy:
  * production — each detection's real long window + the account age guard (honest; on a young
    account most detections will abstain, which is the correct answer).
  * eval — a single recent window with the age guard disabled, to exercise the wiring and see
    findings fire on freshly generated telemetry (the same mode our per-detection validations use).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from coda_core.framework.cost_rate import EffectiveRate
from coda_core.providers.arm import AccountConfig, ArmProvider, ThroughputOffer
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow
from coda_core.providers.log_analytics import LogAnalyticsProvider
from coda_core.providers.retail_prices import RetailPricesProvider

MODE_PRODUCTION = "production"
MODE_EVAL = "eval"


@dataclass(frozen=True)
class DetectionContext:
    metrics: AzureMonitorMetricsProvider
    account: str
    account_resource_id: str
    offer: ThroughputOffer
    mode: str                          # MODE_PRODUCTION | MODE_EVAL
    eval_window: TimeWindow            # used only in eval mode
    now: datetime                      # single per-run anchor (stable window keys for LA caching)
    resource_created_at: datetime | None  # effective per-unit age (container, else account)
    scope_provisioned_ru: float | None  # scope's total provisioned RU/s (materiality denominator)
    la: LogAnalyticsProvider | None = None  # Log Analytics (resource-centric) for LA-backed container
                                            # detections (e.g. DX-002); None => those detections skip.
    effective_rate: EffectiveRate | None = None  # customer's bill-derived $/RU/s rate (ADR-0028);
                                                 # None => Cost Management absent → capacity-only findings.

    def window_for(self, production_window: TimeWindow) -> TimeWindow:
        """Pick the detection's production window, or the shared eval window in eval mode."""
        return self.eval_window if self.mode == MODE_EVAL else production_window

    def created_at(self) -> datetime | None:
        """Age guard input: real per-unit age in production, ``None`` (disabled) in eval."""
        return None if self.mode == MODE_EVAL else self.resource_created_at


@dataclass(frozen=True)
class AccountDetectionContext:
    """Context for account-scoped detections and optional account-level enrichment.

    The first account-scoped detection is DX-008 (multi-region writes); DX-014 (serverless account)
    and DX-016 (consistency) reuse this scope layer. The exact ARM offer tuple lets account
    detections quantify capacity without re-enumeration or shared-throughput double counting.
    ``effective_rate`` carries the optional customer-bill rate derived once by the runner, including
    whether it came from account rows or the subscription billing-latency fallback, so account-level
    findings can add auditable savings without embedding billing logic in detectors.
    """

    metrics: AzureMonitorMetricsProvider
    account: str
    account_resource_id: str
    config: AccountConfig
    mode: str
    eval_window: TimeWindow
    now: datetime
    scope_provisioned_ru: float | None
    resource_group: str = ""
    arm: ArmProvider | None = None
    retail_prices: RetailPricesProvider | None = None
    throughput_offers: tuple[ThroughputOffer, ...] = ()
    la: LogAnalyticsProvider | None = None
    effective_rate: EffectiveRate | None = None

    def window_for(self, production_window: TimeWindow) -> TimeWindow:
        """Pick the detection's production window, or the shared eval window in eval mode."""
        return self.eval_window if self.mode == MODE_EVAL else production_window


@dataclass(frozen=True)
class DatabaseDetectionContext:
    """Context for database-scoped detections — i.e. shared-throughput databases (DX-003).

    Carries the Log Analytics provider (resource-centric) since database-scoped detections read
    ``CDB*`` data-plane logs.
    """

    la: LogAnalyticsProvider | None = None  # resource-centric LA; None => gated by the capability layer
    account: str = ""
    account_resource_id: str = ""
    database: str = ""
    shared_ru: float = 0.0      # the database-level shared throughput (RU/s)
    mode: str = ""
    eval_window: TimeWindow | None = None
    now: datetime | None = None

    def window_for(self, production_window: TimeWindow) -> TimeWindow:
        return self.eval_window if self.mode == MODE_EVAL else production_window


@dataclass(frozen=True)
class ServerlessDetectionContext:
    """Context for serverless-container detections (DX-018).

    Serverless containers have no throughput offer, so they are enumerated directly (database +
    container) and diagnosed on a dedicated pass gated by the account's ``EnableServerless``
    capability. Metrics-only (no provisioned RU, no Log Analytics requirement).
    """

    metrics: AzureMonitorMetricsProvider
    account: str
    account_resource_id: str
    database: str
    container: str
    mode: str
    eval_window: TimeWindow
    now: datetime
    la: LogAnalyticsProvider | None = None  # Log Analytics for LA-backed serverless detections (DX-002)

    def window_for(self, production_window: TimeWindow) -> TimeWindow:
        return self.eval_window if self.mode == MODE_EVAL else production_window

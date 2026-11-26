"""Throughput savings: regional billed quantity times a matching amortized meter price (ADR-0080).

Cost divided by usage gives a discount-inclusive price per billing unit. It cannot also tell us
how many such units a physical capacity change removes. Keep those two facts separate; never use
retail prices or interpret the estimate as a guaranteed reduction in the next invoice.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Literal, TypedDict

if TYPE_CHECKING:
    from coda_core.providers.arm import AccountConfig

# Annual-average month used for projection, not the number of hours in a particular invoice.
HOURS_PER_MONTH = 730.0

# The Cosmos provisioned-throughput meter is priced per **100 RU/s** (the meter unit). cost / usage is
# therefore $ per 100-RU/s-hour; divide by this to get $ per (1 RU/s)-hour.
THROUGHPUT_METER_UNIT_RU = 100.0
STANDARD_METER = "100 RU/s"
MULTI_WRITE_METER = "100 Multi-master RU/s"
THROUGHPUT_METERS = (STANDARD_METER, MULTI_WRITE_METER)


def throughput_meter(config: AccountConfig | None) -> str | None:
    """Select a meter only for an identified, consistent topology and a paid provisioned account."""
    if config is None or config.is_serverless or config.free_tier is not False:
        return None
    names = {name.strip().casefold() for name in config.location_names if name.strip()}
    if (config.region_count < 1 or len(names) != config.region_count
            or len(config.location_names) != config.region_count):
        return None
    if config.multi_region_writes_enabled is False and config.write_region_count == 1:
        return STANDARD_METER
    if (config.multi_region_writes_enabled is True and config.region_count >= 2
            and config.write_region_count == config.region_count):
        return MULTI_WRITE_METER
    return None


@dataclass(frozen=True)
class BillingQuantity:
    """Explain how the input (already the idle floor delta for autoscale) becomes meter units."""

    meter: str
    input_ru: float
    input_basis: str
    affected_regions: int
    zone_premium_regions: int
    mode_factor: float
    meter_units_per_hour: float

    def monthly_estimate(self, rate: EffectiveRate) -> float | None:
        """Price billed units directly; the hourly unit price already reflects the selected meter."""
        if rate.basis.get("meters") != [self.meter]:
            return None
        amount = self.meter_units_per_hour * rate.unit_price_per_100rus_hour * HOURS_PER_MONTH
        return amount if math.isfinite(amount) and amount > 0 else None


def billing_quantity(config: AccountConfig, meter: str, mode: str, recovered_ru: float,
                     *, already_regional: bool) -> BillingQuantity | None:
    """Translate offer-local capacity or DX-008's already-regional amount exactly once."""
    if (meter != throughput_meter(config) or meter not in THROUGHPUT_METERS
            or mode not in {"manual", "autoscale"} or not math.isfinite(recovered_ru) or recovered_ru <= 0):
        return None
    if already_regional:
        if mode != "manual" or meter != MULTI_WRITE_METER:
            return None  # Only DX-008 supplies a regional input.
        return BillingQuantity(meter, recovered_ru, "removed_regional_ru", config.region_count - 1,
                               0, 1.0, recovered_ru / THROUGHPUT_METER_UNIT_RU)
    zones = 0
    factor = 1.0
    if meter == STANDARD_METER:
        if mode == "autoscale":
            factor = 1.5
        else:
            count = config.zone_redundant_region_count
            if type(count) is not int or not 0 <= count <= config.region_count:
                return None
            zones = count
    units = recovered_ru / THROUGHPUT_METER_UNIT_RU * (config.region_count + 0.25 * zones) * factor
    return BillingQuantity(meter, recovered_ru, "offer_ru_per_region", config.region_count, zones,
                           factor, units) if math.isfinite(units) else None


RATE_SOURCE_CUSTOMER_AMORTIZED_BILL = "customer_amortized_bill"
RATE_SCOPE_ACCOUNT = "account"
RATE_SCOPE_SUBSCRIPTION_FALLBACK = "subscription_fallback"
EffectiveRateScope = Literal["account", "subscription_fallback"]
APPROVED_EFFECTIVE_RATE_SCOPES = frozenset(
    {
        RATE_SCOPE_ACCOUNT,
        RATE_SCOPE_SUBSCRIPTION_FALLBACK,
    }
)


class EffectiveRateBasis(TypedDict):
    """Auditable customer-bill inputs and provenance retained with an effective rate."""

    amortized_cost: float
    billed_usage_100rus_hours: float
    meters: list[str]
    hours_per_month: float
    rate_source: Literal["customer_amortized_bill"]
    rate_scope: EffectiveRateScope


@dataclass(frozen=True)
class EffectiveRate:
    """A customer's discount-inclusive Cosmos throughput rate, derived from their amortized bill.

    ``usd_per_ru_month`` is the legacy field for the monthly price per billing-equivalent RU/s,
    in the bill's currency (not necessarily USD). ``rate_scope`` distinguishes account rows from the bounded
    subscription fallback used during account billing latency. ``basis`` records the same scope plus
    the inputs (cost, usage, meters, currency) so every dollar figure is auditable back to the
    customer's invoice.
    """

    usd_per_ru_month: float
    currency: str
    unit_price_per_100rus_hour: float
    rate_scope: EffectiveRateScope
    basis: EffectiveRateBasis

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CostEstimateIssue:
    """Account-level enrichment failure, not a failed detector or a fabricated zero-dollar estimate."""

    code: str
    message: str
    user_action: str
    query_scope: str
    http_status: int | None = None

    def as_dict(self) -> dict[str, object]:
        """Keep only safe, authored explanations and structured provenance in report output."""
        return {key: value for key, value in asdict(self).items() if value is not None}


def cost_estimate_issue(
    reason: str, query_scope: str, *, http_status: int | None = None,
) -> CostEstimateIssue:
    """Map a known failure class to guidance without forwarding external exception prose."""
    explanations = {
        "rate_limited": (
            "Cost Management rate-limited the billing query (HTTP 429).",
            "Wait before retrying; repeated analyses and pre-checks also consume Cost Management quota.",
        ),
        "access_denied": (
            "Cost Management denied access to the billing query.",
            "Use Run Pre-Checks to review cost access and billing policy with your administrator.",
        ),
        "authentication": (
            "The billing query could not authenticate.",
            "Verify your Azure sign-in before retrying. A role assignment is not necessarily the fix.",
        ),
        "timeout": (
            "The Cost Management billing query timed out.",
            "Wait before retrying and check service/network availability.",
        ),
        "service_unavailable": (
            "Cost Management could not complete the billing query because of a service error.",
            "Wait before retrying and check Azure service availability.",
        ),
        "query_failed": (
            "The Cost Management billing query could not be completed or its response processed.",
            "Use Run Pre-Checks to investigate. This failure does not establish a missing permission.",
        ),
        "no_usable_rate": (
            "No usable matching throughput meter rate was available from the account or subscription.",
            "Check billing-data availability and attribution; extra permissions do not create missing usage.",
        ),
        "unknown_billing_configuration": (
            "The paid provisioned-throughput billing configuration could not be established.",
            "Verify the write mode, free-tier setting and region inventory; capacity findings remain available.",
        ),
        "not_configured": (
            "Cost Management enrichment was not configured for this analysis.",
            "Enable cost enrichment in the caller and use Run Pre-Checks to verify read access.",
        ),
    }
    message, action = explanations[reason]
    return CostEstimateIssue(
        code=f"cost_estimate.{reason}",
        message=f"Dollar savings unavailable: {message} Capacity findings remain valid.",
        user_action=action,
        query_scope=query_scope,
        http_status=http_status,
    )


def derive_effective_rate(
    cost: float,
    usage: float,
    currency: str,
    *,
    rate_scope: EffectiveRateScope,
    meters: tuple[str, ...] = (),
) -> EffectiveRate | None:
    """Derive a discount-inclusive $/RU/s-month rate from amortized throughput cost + usage.

    Args:
        cost: Amortized Cosmos provisioned-throughput cost over a window (billing currency).
        usage: Billed throughput usage over the same window (100-RU/s-hours).
        currency: Billing currency of ``cost``.
        rate_scope: Whether the bill rows are account-attributed or the explicitly approved
            subscription fallback used when a successful account query has no derivable rate.
        meters: Exactly one supported throughput meter. Unknown or blended meters are unpriceable.

    Returns:
        An :class:`EffectiveRate`, or ``None`` when no positive billed throughput usage exists —
        in which case CODA must NOT assert a dollar figure (it abstains to capacity only). Honesty
        over coverage (first principle #1): a derived rate with no usage behind it would be a guess.
    """
    if rate_scope not in APPROVED_EFFECTIVE_RATE_SCOPES:
        raise ValueError(f"unsupported effective-rate scope: {rate_scope}")
    if (
        not math.isfinite(cost)
        or not math.isfinite(usage)
        or cost <= 0
        or usage <= 0
        or not isinstance(currency, str)
        or not currency.strip()
        or len(meters) != 1 or meters[0] not in THROUGHPUT_METERS
    ):
        return None
    unit_price_per_100rus_hour = cost / usage
    usd_per_ru_month = unit_price_per_100rus_hour / THROUGHPUT_METER_UNIT_RU * HOURS_PER_MONTH
    if not math.isfinite(unit_price_per_100rus_hour) or not math.isfinite(usd_per_ru_month):
        return None
    return EffectiveRate(
        usd_per_ru_month=usd_per_ru_month,
        currency=currency,
        unit_price_per_100rus_hour=unit_price_per_100rus_hour,
        rate_scope=rate_scope,
        basis={"amortized_cost": round(cost, 4), "billed_usage_100rus_hours": round(usage, 4),
               "meters": list(meters), "hours_per_month": HOURS_PER_MONTH,
               "rate_source": RATE_SOURCE_CUSTOMER_AMORTIZED_BILL,
               "rate_scope": rate_scope},
    )


def monthly_savings(recovered_ru: float, rate: EffectiveRate | None) -> float | None:
    """Legacy one-copy conversion for a quantity already expressed in billing-equivalent RU/s.

    Do not pass unconverted physical offer capacity here. Report producers use
    :meth:`BillingQuantity.monthly_estimate` after establishing regional billing scope.
    """
    if (
        rate is None
        or not math.isfinite(recovered_ru)
        or recovered_ru <= 0
        or not math.isfinite(rate.usd_per_ru_month)
        or rate.usd_per_ru_month <= 0
    ):
        return None
    amount = recovered_ru * rate.usd_per_ru_month
    return amount if math.isfinite(amount) and amount > 0 else None


__all__ = [
    "EffectiveRate", "derive_effective_rate", "monthly_savings",
    "CostEstimateIssue", "cost_estimate_issue",
    "HOURS_PER_MONTH", "THROUGHPUT_METER_UNIT_RU",
    "APPROVED_EFFECTIVE_RATE_SCOPES",
    "EffectiveRateScope",
    "RATE_SCOPE_ACCOUNT",
    "RATE_SCOPE_SUBSCRIPTION_FALLBACK",
    "RATE_SOURCE_CUSTOMER_AMORTIZED_BILL",
]

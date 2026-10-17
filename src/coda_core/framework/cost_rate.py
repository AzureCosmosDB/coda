"""Effective $/RU/s rate derivation — the FinOps dollar surface (ADR-0028).

CODA never uses Azure **list** prices to estimate savings — that was cosmic-kusto's over-promise trap
(list price × a `capture_rate`/`rebase` discount fudge). Instead it derives the customer's **own
effective rate** from their **amortized** Cosmos provisioned-throughput bill (Cost Management), so
every reservation, savings plan, EA/CSP discount, region multiplier, and mode premium is *already
baked in* — because it is the customer's actual invoice, not an assertion (first principle #1).

The derivation is **duration-independent**. The throughput meter's billed *usage* is in
100-RU/s-hours, so ``cost / usage`` is a true unit price ($ per 100-RU/s-hour) regardless of how many
hours the capacity was actually provisioned. (Dividing total cost by ``provisioned_ru × window_hours``
would understate the rate for any resource provisioned for only part of the window — e.g. bursty
fixtures.) Monthly savings for a finding is then just ``recovered_ru × rate`` — no assumptions.

This module is intentionally provider-agnostic: it takes primitive cost/usage/currency, mirroring the
``DataProvider`` seam, so the rate logic carries no Cost-Management coupling.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Literal, TypedDict

# Azure bills a "month" as 730 hours (8760 / 12). Used only to express the hourly effective unit price
# as a monthly figure for human-facing savings ("$X / month"), never as a pricing assumption.
HOURS_PER_MONTH = 730.0

# The Cosmos provisioned-throughput meter is priced per **100 RU/s** (the meter unit). cost / usage is
# therefore $ per 100-RU/s-hour; divide by this to get $ per (1 RU/s)-hour.
THROUGHPUT_METER_UNIT_RU = 100.0

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

    ``usd_per_ru_month`` is the headline conversion factor: dollars saved per RU/s recovered per
    month. ``rate_scope`` distinguishes the preferred account-attributed rate from the bounded
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
            "No usable billed throughput rate was available from the account or subscription.",
            "Check billing-data availability and attribution; extra permissions do not create missing usage.",
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
        meters: Which billing meters contributed (carried into ``basis`` for audit).

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
    """Dollars/month saved by recovering ``recovered_ru`` RU/s at the customer's effective rate.

    Returns ``None`` when no rate is available (no Cost Management access or no billed usage) so the
    caller renders a capacity-only finding rather than a fabricated dollar figure.
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

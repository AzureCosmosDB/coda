"""DX-023: Reserved Capacity coverage opportunity.

An account carrying a **material provisioned-throughput baseline** (RU/s it pays for around the clock)
is a candidate for **Azure Cosmos DB reserved capacity** — a 1- or 3-year commitment that discounts
provisioned throughput vs pay-as-you-go. This detection surfaces the *opportunity to evaluate* reserved
capacity; it does **not** compute a saving (that depends on the customer's negotiated rate and any
reservations they already hold, which must be checked in Cost Management).

**Configuration/state** detection: it reads the account's total provisioned throughput (the scope's
provisioned RU/s, already computed by the pipeline). **Advisory** (ADR-0012) — no dollar/RU figure,
because reserved-capacity economics are list-price / commitment decisions the customer validates.
Serverless accounts have no provisioned throughput to reserve. Read-only. Thresholds are **proposals**.

Closes the `reserved_capacity` gap from the cosmic-kusto coverage analysis. (cosmic-kusto scopes this at
the fleet level; CODA's first cut is per-account — a fleet roll-up can follow.)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Proposed floor: below this provisioned baseline, a reservation is rarely worth the commitment
# overhead. Fleet grounding pending (registry marks DX-023 `proposal`).
MIN_BASELINE_RU = 3000.0


@dataclass(frozen=True)
class ReservedCapacityVerdict:
    is_candidate: bool
    # reserved_candidate | below_baseline | serverless | unknown
    root_cause: str
    severity: str  # low | none
    provisioned_ru: float | None
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def detect_reserved_capacity_candidate(
    provisioned_ru: float | None, *, is_serverless: bool
) -> ReservedCapacityVerdict:
    """Classify an account's reserved-capacity opportunity (pure; provisioned RU/s in, verdict out)."""
    method = {"provisioned_ru": provisioned_ru, "is_serverless": is_serverless,
              "min_baseline_ru": MIN_BASELINE_RU}

    def verdict(**kw) -> ReservedCapacityVerdict:
        base = dict(is_candidate=False, root_cause="below_baseline", severity="none",
                    provisioned_ru=provisioned_ru, recommended_action="", methodology=method)
        base.update(kw)
        return ReservedCapacityVerdict(**base)

    if is_serverless:
        return verdict(root_cause="serverless")  # nothing provisioned to reserve
    if provisioned_ru is None:
        return verdict(root_cause="unknown")
    if provisioned_ru < MIN_BASELINE_RU:
        return verdict(root_cause="below_baseline")

    return verdict(
        is_candidate=True, root_cause="reserved_candidate", severity="low",
        recommended_action=(
            f"This account provisions ~{provisioned_ru:,.0f} RU/s around the clock. A stable "
            "provisioned baseline is eligible for Azure Cosmos DB reserved capacity (a 1- or 3-year "
            "commitment that discounts provisioned throughput vs pay-as-you-go). Evaluate reserved "
            "capacity and verify your existing reservation coverage and negotiated rate in Cost "
            "Management before committing."
        ),
    )

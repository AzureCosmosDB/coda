"""DX-023: direct provisioned accounts to a billing-scope review, not a reservation purchase."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ReservedCapacityVerdict:
    """Reservation review needs no throughput-size threshold or severity band."""

    root_cause: str
    severity: str
    recommended_action: str
    methodology: dict

    def as_dict(self) -> dict:
        return asdict(self)


def detect_reserved_capacity_candidate(
    provisioned_ru: float | None, *, is_serverless: bool, confirmed_provisioned: bool = False,
) -> ReservedCapacityVerdict:
    """A verified offer confirms capacity mode even when total account capacity is unavailable."""
    if is_serverless:
        reason = "serverless"
    elif confirmed_provisioned or (provisioned_ru is not None and provisioned_ru > 0):
        reason = "reservation_review"
    else:
        reason = "unknown"
    review = reason == "reservation_review"
    return ReservedCapacityVerdict(
        reason, "none",
        ("In Cost Management, review reservation recommendations and existing coverage at your "
         "billing scope. Compare hourly billed throughput, contract rates and expected future use "
         "before making a one- or three-year commitment.") if review else "",
        {"configured_ru": provisioned_ru, "is_serverless": is_serverless,
         "root_cause": reason, "visible_observation": review},
    )

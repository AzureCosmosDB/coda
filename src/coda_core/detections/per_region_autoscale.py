"""DX-022: recommend independent scaling for verified autoscale offers, not manual throughput."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Sequence

from coda_core.providers.arm import AccountConfig, ThroughputOffer


@dataclass(frozen=True)
class PrpaVerdict:
    """Keep unknown configuration distinct from an inapplicable or already enabled feature."""

    is_candidate: bool
    root_cause: str
    severity: str
    region_count: int
    is_pppra_enabled: bool | None
    recommended_action: str
    methodology: dict

    def as_dict(self) -> dict:
        return asdict(self)


def detect_prpa_candidate(
    config: AccountConfig, offers: Sequence[ThroughputOffer], *, inventory_complete: bool = True,
) -> PrpaVerdict:
    """One verified autoscale offer suffices even if another offer could not be enumerated."""
    count = sum(o.mode == "autoscale" for o in offers)
    if config.is_serverless:
        reason = "serverless"
    elif config.is_pppra_enabled is True:
        reason = "already_enabled"
    elif not count:
        reason = "no_autoscale_offers" if inventory_complete else "unknown_offers"
    elif config.is_pppra_enabled is not False:
        reason = "unknown_setting"
    else:
        reason = "prpa_candidate"
    eligible = reason == "prpa_candidate"
    return PrpaVerdict(
        eligible, reason, "high" if eligible else "none", config.region_count, config.is_pppra_enabled,
        ("Enable dynamic autoscale on the account so that physical partitions and regions can scale "
         "independently. No downtime is required. The cost benefit depends on hourly demand; "
         "this configuration does not establish a savings amount.") if eligible else "",
        {"region_count": config.region_count, "is_pppra_enabled": config.is_pppra_enabled,
         "is_serverless": config.is_serverless, "confirmed_autoscale_offers": count,
         "inventory_complete": inventory_complete, "root_cause": reason},
    )

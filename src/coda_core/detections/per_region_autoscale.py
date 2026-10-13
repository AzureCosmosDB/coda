"""DX-022: Per-Region Provisioned Autoscale (PRPA) opportunity.

A **multi-region autoscale** account *without* Per-Region Provisioned Autoscale scales every region's
throughput to the **hottest** region's level — so idle replica regions are provisioned (and billed) at
the busy region's autoscale level. **PRPA** lets each region scale to *its own* demand, reclaiming the
idle-region headroom.

This is a **configuration/state** detection (ARM only): a multi-region account with PRPA **not**
enabled is a candidate to evaluate. It is **advisory** (ADR-0012) — the benefit depends on the account
actually using autoscale and on the per-region demand skew, both of which the customer confirms — so it
asserts no dollar/RU figure. Read-only. The configuration predicate is deterministic and validated;
the customer-specific benefit remains explicitly unquantified.

Data source: `AccountConfig.region_count` + `is_pppra_enabled` (ARM). Closes the `prpa_candidate` gap
from the cosmic-kusto coverage analysis.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from coda_core.providers.arm import AccountConfig


@dataclass(frozen=True)
class PrpaVerdict:
    is_candidate: bool
    # prpa_candidate | already_enabled | single_region | serverless
    root_cause: str
    severity: str  # low | none
    region_count: int
    is_pppra_enabled: bool
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def detect_prpa_candidate(config: AccountConfig) -> PrpaVerdict:
    """Classify an account's PRPA opportunity (pure; ARM config in, verdict out)."""
    method = {"region_count": config.region_count, "is_pppra_enabled": config.is_pppra_enabled,
              "is_serverless": config.is_serverless}

    def verdict(**kw) -> PrpaVerdict:
        base = dict(
            is_candidate=False, root_cause="single_region", severity="none",
            region_count=config.region_count, is_pppra_enabled=config.is_pppra_enabled,
            recommended_action="", methodology=method,
        )
        base.update(kw)
        return PrpaVerdict(**base)

    if config.is_serverless:
        return verdict(root_cause="serverless")  # serverless has no provisioned per-region autoscale
    if config.region_count < 2:
        return verdict(root_cause="single_region")  # PRPA only helps multi-region accounts
    if config.is_pppra_enabled:
        return verdict(root_cause="already_enabled")

    return verdict(
        is_candidate=True, root_cause="prpa_candidate", severity="low",
        recommended_action=(
            f"This account spans {config.region_count} regions without Per-Region Provisioned "
            "Autoscale (PRPA). If it uses autoscale throughput, every region is scaled to the busiest "
            "region's level, so idle replica regions are over-provisioned. Enabling PRPA lets each "
            "region scale to its own demand and reclaims that idle-region headroom. Evaluate PRPA "
            "(it applies to autoscale throughput; confirm your per-region demand skew first)."
        ),
    )

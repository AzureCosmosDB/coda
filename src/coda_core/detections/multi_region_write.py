"""DX-008: Multi-region writes antipattern and regional capacity footprint.

Multi-region writes can serve local writes or provide availability. Account configuration describes
which regions accept writes, not how an application will reach them during an outage.

* **Mongo / Cassandra / Gremlin / Table API + multi-region writes** — Low advisory to verify
  client write failover, not evidence of unsupported writes or a misconfiguration (ADR-0079).
* **Non-production + multi-region writes** — dev/test/stage workloads don't need RTO=0 write failover;
  the feature adds write-conflict surface, while retaining unnecessary regions repeats provisioned
  throughput in every region. A common real case is production config cloned into a test/QA account.
* **Single write region + the flag set (any environment)** — a *tripwire*: the feature yields neither
  benefit with one region (write failover needs a second region; low-latency writes need >=2). Adding
  another region separately repeats provisioned throughput there. This applies in production too.

A production NoSQL account with multi-region writes across two or more write regions is treated as
**legitimate** (active-active / RTO=0 HA) and not flagged.

This is a **configuration/state** detection. ARM throughput offers can quantify configured regional
capacity, but never customer spend: manual throughput ``S`` across ``N`` regions has a global footprint
of ``S * N`` regional RU/s. Only a recommendation that removes unnecessary regions can call
``S * (N - 1)`` removable. Toggling multi-write while retaining the regions does not reduce that
footprint. Serverless and any autoscale inventory fail closed. Read-only / diagnose-only.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass, field

from coda_core.framework.env_classifier import classify_environment
from coda_core.providers.arm import AccountConfig, ThroughputOffer

# Configuration to inspect, not assumptions about which client the customer uses.
_CLIENT_CHECKS = {
    "mongo": ("MongoDB", "Check the preferred write region in your connection settings."),
    "cassandra": ("Cassandra", "Check the driver's load-balancing policy and preferred regions."),
    "gremlin": ("Gremlin", "Check whether the client uses the global endpoint or selects regional endpoints itself."),
    "table": ("Table", "Check regional routing and fallback for the specific Table SDK and version you use."),
}


@dataclass(frozen=True)
class MultiRegionWriteVerdict:
    is_antipattern: bool
    # {mongo,cassandra,gremlin,table}_multi_region_writes | nonprod_multi_region_writes |
    # single_region_multi_region_writes_tripwire | legitimate_ha | not_multi_region_writes
    root_cause: str
    severity: str  # high | medium | low | none
    multi_region_writes_enabled: bool
    write_region_count: int
    is_mongo: bool
    is_non_prod: bool
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _regional_capacity(
    config: AccountConfig,
    offers: Sequence[ThroughputOffer],
    *,
    remove_extra_regions: bool,
    inventory_issues: tuple[str, ...],
) -> dict:
    """Quantify only complete, unique manual-throughput inventory from ARM."""
    evidence = {
        "status": "unavailable",
        "basis": "arm_throughput_offers",
        "region_count": config.region_count,
        "offer_count": len(offers),
        "dollar_estimate": None,
    }
    if config.is_serverless:
        return {**evidence, "reason": "serverless_has_no_provisioned_throughput_footprint"}
    if inventory_issues:
        return {**evidence, "reason": "incomplete_offer_inventory", "issues": inventory_issues}
    if not offers:
        return {**evidence, "reason": "no_throughput_offers"}
    identities = [(offer.database, offer.container, offer.level) for offer in offers]
    if len(identities) != len(set(identities)):
        return {**evidence, "reason": "duplicate_throughput_offer_inventory"}
    if any(offer.mode != "manual" for offer in offers):
        return {
            **evidence,
            "reason": "autoscale_or_mixed_inventory_not_quantified",
            "offer_modes": sorted({offer.mode for offer in offers}),
        }
    if config.region_count < 1 or any(offer.provisioned_ru <= 0 for offer in offers):
        return {**evidence, "reason": "invalid_region_or_throughput_inventory"}

    per_region = round(sum(offer.provisioned_ru for offer in offers), 2)
    global_footprint = round(per_region * config.region_count, 2)
    removable = (
        round(per_region * (config.region_count - 1), 2)
        if remove_extra_regions and config.region_count > 1
        else None
    )
    return {
        **evidence,
        "status": "quantified",
        "configured_per_region_ru": per_region,
        "global_regional_ru": global_footprint,
        "removable_extra_region_ru": removable,
        "formula": {
            "global_regional_ru": "configured_per_region_ru * region_count",
            "removable_extra_region_ru": (
                "configured_per_region_ru * (region_count - 1)"
                if remove_extra_regions
                else None
            ),
        },
        "removal_condition": (
            "Remove the unnecessary extra regions; disabling multi-write alone does not change "
            "throughput provisioned in retained regions."
            if remove_extra_regions
            else "No region-removal recommendation is made by this classification."
        ),
        "offers": [offer.as_dict() for offer in offers],
    }


def detect_multi_region_writes(
    config: AccountConfig,
    offers: Sequence[ThroughputOffer] = (),
    *, inventory_issues: tuple[str, ...] = (),
) -> MultiRegionWriteVerdict:
    """Classify multi-region writes and attach defensible ARM capacity evidence."""
    env = classify_environment(config.name, config.tags, config.subscription_name)
    non_prod = env.is_non_prod
    method = {
        "env_inferred": env.inferred_env,
        "env_basis": env.signal,
        "api_kind": config.api_kind,
        "write_region_count": config.write_region_count,
        "region_count": config.region_count,
    }

    def verdict(**kw) -> MultiRegionWriteVerdict:
        base = dict(
            is_antipattern=False, root_cause="not_multi_region_writes", severity="none",
            multi_region_writes_enabled=bool(config.multi_region_writes_enabled),
            write_region_count=config.write_region_count, is_mongo=config.is_mongo,
            is_non_prod=non_prod, recommended_action="", methodology=method,
        )
        base.update(kw)
        base["methodology"] = {
            **method,
            "regional_capacity": _regional_capacity(
                config,
                offers,
                inventory_issues=inventory_issues,
                remove_extra_regions=base["root_cause"] == "nonprod_multi_region_writes",
            ),
        }
        return MultiRegionWriteVerdict(**base)

    if not config.multi_region_writes_enabled:
        return verdict(root_cause="not_multi_region_writes")

    if config.api in _CLIENT_CHECKS:
        api_label, check = _CLIENT_CHECKS[config.api]
        method.update(api_family=api_label, client_write_failover="not_assessed")
        return verdict(
            is_antipattern=True, root_cause=f"{config.api}_multi_region_writes", severity="low",
            recommended_action=(
                f"Verify client write failover for your {api_label} application. {check} "
                "Confirm in a controlled test whether writes resume within your recovery target "
                "when the usual write region is unavailable. CODA has not tested your client."
            ),
        )

    # Single write region + the flag set = latent tripwire regardless of environment (#8): the
    # feature delivers neither benefit with one region (RTO=0 write failover needs a second region
    # to fail over to; low-latency local writes need >=2 regions). Production single-region
    # multi-master is the same trip-wire.
    if config.write_region_count < 2:
        return verdict(
            is_antipattern=True, root_cause="single_region_multi_region_writes_tripwire",
            severity="low",
            recommended_action=(
                "Multi-region writes are enabled but the account has a single write region — so the "
                "feature delivers no benefit today (RTO=0 write failover needs a second region; "
                "low-latency local writes need at least two regions). Disable multi-region writes to "
                "remove the tripwire unless a second write region is imminent and justified."
            ),
        )

    # Two or more write regions in production: treated as legitimate active-active / RTO=0 HA.
    if not non_prod:
        return verdict(root_cause="legitimate_ha")

    # Non-production with >=2 write regions: doesn't need RTO=0 write failover.
    return verdict(
        is_antipattern=True, root_cause="nonprod_multi_region_writes", severity="medium",
        recommended_action=(
            "Multi-region writes are enabled across "
            f"{config.write_region_count} write regions on a non-production account, which does "
            "not need RTO=0 write failover. Remove unnecessary extra regions to eliminate their "
            "regional throughput footprint, then disable multi-region writes to remove the conflict "
            "surface. Disabling multi-region writes while retaining the regions does not reduce "
            "throughput provisioned in those regions."
        ),
    )

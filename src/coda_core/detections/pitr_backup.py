"""DX-019: paid continuous-backup storage on a non-production account.

Cosmos DB offers periodic and continuous backup modes (ARM ``backupPolicy.type``). Continuous
backup has three recognized retention tiers:

* **Continuous7Days** has no backup-storage charge.
* **Continuous30Days** and **Continuous35Days** have a monthly backup-storage charge.
* Restore operations are charged separately for every continuous tier.

DX-019 identifies only the paid 30-day and 35-day storage tiers on a positively classified
**non-production** (dev/test/stage/sandbox) account. A production or unknown environment is treated
as a legitimate protection choice. Missing or unrecognized continuous tiers abstain because their
backup-storage charge cannot be established from configuration.

This is a **configuration/state** detection (ARM only — no workload, metrics, or Log Analytics) and a
**qualitative** finding per ADR-0012: it surfaces the paid retention trade-off and asks the customer
to confirm the required recovery window; it does not assert a dollar figure. Read-only /
diagnose-only.

Data source: ``AccountConfig.backup_mode`` / ``continuous_backup_tier`` (ARM), classified against
``framework.env_classifier``. See ``docs/exploration/cosmic-kusto-gap-buildability.md`` (this closes
the ``pitr_non_prod`` gap identified there) and ADR-0046 for the pricing correction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from coda_core.framework.env_classifier import classify_environment
from coda_core.providers.arm import AccountConfig


def _is_continuous(backup_mode: str | None) -> bool:
    """True when the account's backup policy is Continuous (PITR), tolerant of casing/qualifiers."""
    return (backup_mode or "").strip().lower().startswith("continuous")


def _continuous_tier_days(tier: str | None) -> int | None:
    """Return retention days only for an exact recognized ARM continuous-tier enum."""
    recognized = {
        "continuous7days": 7,
        "continuous30days": 30,
        "continuous35days": 35,
    }
    return recognized.get((tier or "").strip().lower())


@dataclass(frozen=True)
class PitrBackupVerdict:
    is_antipattern: bool
    # nonprod_paid_continuous_backup | uncharged_7day_backup | unknown_continuous_tier
    # | legitimate_prod_backup | periodic_backup | unknown
    root_cause: str
    severity: str  # medium | none
    backup_mode: str | None
    continuous_backup_tier: str | None
    is_non_prod: bool
    recommended_action: str
    methodology: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def detect_pitr_on_nonprod(config: AccountConfig) -> PitrBackupVerdict:
    """Classify an account's backup configuration (pure; ARM config in, verdict out)."""
    env = classify_environment(config.name, config.tags, config.subscription_name)
    method = {
        "backup_mode": config.backup_mode,
        "continuous_backup_tier": config.continuous_backup_tier,
        "env_inferred": env.inferred_env,
        "env_basis": env.signal,
    }

    def verdict(**kw) -> PitrBackupVerdict:
        base = dict(
            is_antipattern=False, root_cause="periodic_backup", severity="none",
            backup_mode=config.backup_mode, continuous_backup_tier=config.continuous_backup_tier,
            is_non_prod=env.is_non_prod, recommended_action="", methodology=method,
        )
        base.update(kw)
        return PitrBackupVerdict(**base)

    if config.backup_mode is None:
        # ARM didn't surface a backup policy — don't guess.
        return verdict(root_cause="unknown")
    if not _is_continuous(config.backup_mode):
        # Periodic (the default) carries no continuous premium — nothing to flag.
        return verdict(root_cause="periodic_backup")
    if not env.is_non_prod:
        # Continuous backup on a production (or unknown → treated as prod) account is legitimate.
        return verdict(root_cause="legitimate_prod_backup")

    tier_days = _continuous_tier_days(config.continuous_backup_tier)
    if tier_days == 7:
        return verdict(
            root_cause="uncharged_7day_backup",
            recommended_action=(
                "Continuous7Days has no backup-storage charge. Restore operations are charged "
                "separately for all continuous backup tiers."
            ),
        )
    if tier_days not in {30, 35}:
        return verdict(
            root_cause="unknown_continuous_tier",
            recommended_action=(
                "Confirm the continuous backup tier before evaluating backup-storage cost; the "
                "reported tier is missing or unrecognized."
            ),
        )

    tier_label = config.continuous_backup_tier
    return verdict(
        is_antipattern=True,
        root_cause="nonprod_paid_continuous_backup",
        severity="medium",
        recommended_action=(
            f"This {env.inferred_env} (non-production) account uses continuous backup / point-in-time "
            f"restore ({tier_label}), which has a monthly backup-storage charge. Confirm the required "
            "recovery window and evaluate switching to Continuous7Days if a 7-day window is "
            "sufficient; that tier has no backup-storage charge and does not require migrating the "
            "account. The tradeoff is losing restore points older than seven days. Restore operations "
            "are charged separately for every continuous tier."
        ),
    )

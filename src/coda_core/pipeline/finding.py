"""The uniform diagnostic output contract.

Every detection, whatever its internal verdict shape, is translated by the pipeline into a
:class:`Finding`. This is the single contract the rollup, the report, and (later) the MCP/Portal
surfaces consume. It deliberately makes **abstentions** and **clean results** first-class — a
diagnostic tool that only ever emits problems can't be trusted to have actually looked.

Honesty hooks (these exist because unvalidated thresholds are CODA's top risk):
  * ``status`` distinguishes a real finding from "ran, nothing wrong" from "couldn't judge".
  * ``threshold_status`` flags whether the cutoffs behind a finding are fleet-validated or still a
    proposal — so nothing masquerades as validated in a customer-facing report.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Finding.status
STATUS_FINDING = "finding"            # a problem was detected
STATUS_NOT_DETECTED = "not_detected"  # the detection ran and found nothing
STATUS_ABSTAINED = "abstained"        # insufficient data to judge (ADR-0008)

# Finding.threshold_status
THRESHOLD_PROPOSAL = "proposal"       # cutoffs not yet validated against fleet data
THRESHOLD_VALIDATED = "validated"


@dataclass(frozen=True)
class UnitRef:
    """The resource a finding is about (the Selection unit).

    Carries both the human names (account/database/container) and the **full ARM resource id**
    (``resource_id``) so an agent or the Agent Kit can act on the exact resource and locate it in the
    customer's code/config (the account endpoint + database + container names are the strings that
    appear in connection strings and SDK calls).
    """

    account: str
    database: str
    container: str | None  # None = database-level (shared) offer
    level: str             # "container" | "database" | "account"
    resource_id: str | None = None  # full ARM id of the unit (account / sqlDatabases / containers)

    def label(self) -> str:
        """Stable, compact display label; never use it as a resource identity."""
        if self.level == "account":
            return f"{self.account} (account)"
        return f"{self.database}/{self.container}" if self.container else f"{self.database} (shared)"

    def canonical_identity(self) -> tuple[str, str, str, str | None]:
        """Structured resource identity used by correlation instead of the lossy display label."""
        return (self.level, self.account, self.database, self.container)

    def is_same_resource(self, other: UnitRef) -> bool:
        """Match structured identity and, when both are present, normalized ARM resource IDs."""
        if self.canonical_identity() != other.canonical_identity():
            return False
        if self.resource_id is None or other.resource_id is None:
            return True
        return _normalize_resource_id(self.resource_id) == _normalize_resource_id(other.resource_id)

    def describe(self) -> str:
        """Human-readable resource path for reports — unambiguous about what each name is."""
        if self.level == "account":
            return f"account `{self.account}`"
        if self.container:
            return f"container `{self.container}` (database `{self.database}`)"
        return f"database `{self.database}` (shared throughput)"

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    """One detection's result for one unit, in the uniform pipeline contract."""

    detection_id: str          # e.g. "DX-001"
    title: str                 # short human title
    unit: UnitRef
    status: str                # STATUS_*
    severity: str              # high | medium | low | none
    summary: str               # one-line human explanation
    recommended_action: str
    agent_kit_rule: str | None
    threshold_status: str      # THRESHOLD_*
    recoverable_ru: float | None = None         # RU/s recoverable (right-size delta or idle floor)
    materiality_pct: float | None = None        # finding RU/s as % of scope provisioned RU/s
    # Dollar estimates carry explicit provenance. Customer-bill estimates participate in rollups;
    # retail-list estimates remain finding-local so unlike bases are never presented as one total.
    estimated_monthly_savings: float | None = None  # recovered RU/s × customer's effective $/RU/s-month
    savings_currency: str | None = None             # billing currency of estimated_monthly_savings
    savings_basis: str | None = None  # customer_amortized_bill | azure_retail_price
    evidence: dict = field(default_factory=dict)
    # Set by the rollup when another finding subsumes this one (e.g. idle subsumes over-provision).
    superseded_by: str | None = None
    # Explicit detector-authored relationship request. The rollup resolves only valid declarations.
    related_to: str | None = None
    # Set by the rollup after validating an unambiguous same-resource actionable parent.
    related_parent: str | None = None

    def is_actionable(self) -> bool:
        """A real finding that is neither superseded nor nested under an actionable parent."""
        return (
            self.status == STATUS_FINDING
            and self.superseded_by is None
            and self.related_parent is None
        )

    def with_superseded_by(self, detection_id: str) -> Finding:
        return Finding(**{**asdict(self), "unit": self.unit, "superseded_by": detection_id})

    def with_related_parent(self, detection_id: str) -> Finding:
        """Return a copy resolved as a related signal under ``detection_id``."""
        return Finding(**{**asdict(self), "unit": self.unit, "related_parent": detection_id})

    def as_dict(self) -> dict:
        d = asdict(self)
        d["unit"] = self.unit.as_dict()
        return d


def _normalize_resource_id(resource_id: str) -> str:
    """Normalize ARM IDs for their case-insensitive, slash-delimited identity semantics."""
    return resource_id.strip().rstrip("/").casefold()

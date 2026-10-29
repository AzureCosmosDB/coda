"""ARM control-plane provider: authoritative Cosmos throughput config + inventory.

Reads the **user-configured** throughput (manual RU/s, or autoscale max RU/s) and enumerates
databases/containers via ``azure-mgmt-cosmosdb``. This is the authoritative source for a
detection's provisioned RU, throughput **mode** (manual/autoscale), and **offer level**
(container vs shared database) — the Azure Monitor metric's provisioned value is an internal
burst ceiling, not what the customer set (DX-001 §B2).

Auth: control-plane **Azure RBAC** (Reader is sufficient), injected as a ``TokenCredential`` —
separate from the Cosmos data-plane RBAC used by the data SDK.

**Read-only by design.** CODA is a diagnostic tool and never mutates customer resources. This
provider uses only ``get_*`` / ``list_*`` operations; the SDK's ``begin_*`` create/update/delete/
migrate operations are intentionally never called. Remediations (including migrations) are
*recommendations* the customer applies via the Cosmos DB Agent Kit + their own agent.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.cosmosdb import CosmosDBManagementClient


@dataclass(frozen=True)
class ThroughputOffer:
    """One provisioned-throughput offer (where a customer set RU/s).

    A container with dedicated throughput is a container-level offer. A container with no
    dedicated throughput draws from its database's shared pool (a database-level offer).
    """

    database: str
    container: str | None  # None for a database-level (shared) offer
    level: str  # "container" | "database"
    mode: str  # "manual" | "autoscale"
    provisioned_ru: float  # manual RU/s, or autoscale MAX RU/s (the user-set value)
    minimum_ru: float | None  # ARM minimumThroughput; not inferred to be an autoscale maximum limit

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ContainerIndexing:
    """One container plus the indexing-policy facts DX-024 needs (mode + excluded paths)."""

    database: str
    container: str
    indexing_mode: str | None      # "consistent" | "lazy" | "none" (None when ARM omits it)
    excluded_paths: tuple[str, ...]


def container_indexing_from_arm(database: str, cont) -> ContainerIndexing:
    """Parse an ARM ``SqlContainerGetResults`` into :class:`ContainerIndexing`. Pure (no I/O)."""
    resource = getattr(cont, "resource", None)
    policy = getattr(resource, "indexing_policy", None)
    mode = getattr(policy, "indexing_mode", None)
    mode = str(getattr(mode, "value", mode)).lower() if mode is not None else None
    paths = tuple(
        p.path for p in (getattr(policy, "excluded_paths", None) or ())
        if getattr(p, "path", None)
    )
    return ContainerIndexing(database=database, container=cont.name, indexing_mode=mode,
                             excluded_paths=paths)


def _f(value) -> float | None:
    return float(value) if value is not None else None


def _enum_text(value: object | None) -> str | None:
    """Preserve SDK enums' wire values rather than their qualified Python enum names."""
    return str(getattr(value, "value", value)) if value is not None else None


def _is_no_offer_error(exc: Exception) -> bool:
    """True if a throughput read means "this resource has no provisioned offer".

    Two distinct cases collapse to the same answer: a dedicated container / un-provisioned database
    returns ``404`` (``ResourceNotFoundError``), and a **serverless** account returns ``400`` with
    "Reading or replacing offers is not supported for serverless accounts". Both mean: no offer here.
    Any other ``HttpResponseError`` is a real failure and must propagate.
    """
    if isinstance(exc, ResourceNotFoundError):
        return True
    msg = str(getattr(exc, "message", "") or exc)
    return "serverless" in msg.lower() and "offer" in msg.lower()


@dataclass(frozen=True)
class AccountConfig:
    """Account-level configuration/state read from ARM (the input to account-scoped detections).

    Pure data — no I/O — so detections and parsing can be unit-tested offline.
    """

    name: str
    api_kind: str                 # ARM ``kind`` (e.g. "GlobalDocumentDB", "MongoDB")
    is_mongo: bool                # MongoDB API (drivers can't use Cosmos multi-region-write failover)
    multi_region_writes_enabled: bool   # ``enableMultipleWriteLocations``
    write_region_count: int       # number of write locations
    region_count: int             # total locations (read + write)
    location_names: tuple[str, ...]
    tags: dict
    subscription_name: str | None = None  # subscription display name (env-classification signal)
    default_consistency_level: str | None = None  # e.g. "Session", "Strong", "BoundedStaleness"
    is_serverless: bool = False           # EnableServerless capability (a per-account capacity mode)
    is_pppra_enabled: bool = False        # enablePerRegionPerPartitionAutoscale
    capabilities: tuple[str, ...] = ()    # all capability names (e.g. EnableServerless, EnableMongo)
    backup_mode: str | None = None        # ARM ``backupPolicy.type``: "Continuous" (PITR) | "Periodic"
    continuous_backup_tier: str | None = None  # Continuous7Days/30Days/35Days (PITR only)
    backup_migration_status: str | None = None  # nonempty migration metadata prevents merge advice
    backup_migration_target: str | None = None
    all_versions_and_deletes_enabled: bool | None = None  # enablement, not consumer activity

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def api(self) -> str:
        """Normalized Cosmos DB API family: sql | mongo | cassandra | gremlin | table.

        Derived from the ARM ``kind`` plus capability names (e.g. ``EnableCassandra``). Only the
        SQL (Core/NoSQL) API's SDK can use Cosmos DB's multi-region-write failover; the Mongo,
        Cassandra, Gremlin, and Table APIs cannot (see :data:`NON_MULTI_WRITE_APIS`).
        """
        caps = {c.lower() for c in self.capabilities}
        kind = (self.api_kind or "").lower()
        if self.is_mongo or kind == "mongodb" or "enablemongo" in caps:
            return "mongo"
        if "enablecassandra" in caps:
            return "cassandra"
        if "enablegremlin" in caps:
            return "gremlin"
        if "enabletable" in caps:
            return "table"
        return "sql"


# APIs whose SDKs cannot use Cosmos DB's multi-region-write failover — enabling multi-region writes
# on these is a misconfiguration (the RTO=0 HA benefit never materialises). SQL (Core) is excluded.
NON_MULTI_WRITE_APIS = ("mongo", "cassandra", "gremlin", "table")


def account_config_from_arm(acct, *, subscription_name: str | None = None) -> AccountConfig:
    """Parse an ARM ``DatabaseAccountGetResults`` into a :class:`AccountConfig` (pure, no I/O)."""
    kind = getattr(acct, "kind", None) or ""
    cap_names = tuple(n for n in (getattr(c, "name", "") for c in (getattr(acct, "capabilities", None) or [])) if n)
    caps = set(cap_names)
    is_mongo = kind.lower() == "mongodb" or "EnableMongo" in caps
    write_locs = getattr(acct, "write_locations", None) or []
    all_locs = getattr(acct, "locations", None) or []
    names = tuple(
        n for n in (getattr(loc, "location_name", None) for loc in all_locs) if n
    )
    cp = getattr(acct, "consistency_policy", None)
    consistency = getattr(cp, "default_consistency_level", None) if cp is not None else None
    # Backup policy: ContinuousModeBackupPolicy (PITR) has type "Continuous" + a retention tier;
    # PeriodicModeBackupPolicy has type "Periodic". Parse defensively — the property/model may be
    # absent on older API shapes.
    bp = getattr(acct, "backup_policy", None)
    backup_mode = getattr(bp, "type", None) if bp is not None else None
    cont_props = getattr(bp, "continuous_mode_properties", None) if bp is not None else None
    continuous_tier = getattr(cont_props, "tier", None) if cont_props is not None else None
    migration = getattr(bp, "migration_state", None) if bp is not None else None
    migration_status = getattr(migration, "status", None)
    migration_target = getattr(migration, "target_type", None)
    # Older SDK/API models omit this flag. Absence is unknown, never evidence of disabled usage.
    full_fidelity = getattr(acct, "enable_all_versions_and_deletes_change_feed", None)
    return AccountConfig(
        name=getattr(acct, "name", "") or "",
        api_kind=kind,
        is_mongo=is_mongo,
        multi_region_writes_enabled=bool(getattr(acct, "enable_multiple_write_locations", False)),
        write_region_count=len(write_locs),
        region_count=len(all_locs),
        location_names=names,
        tags=dict(getattr(acct, "tags", None) or {}),
        subscription_name=subscription_name,
        default_consistency_level=str(consistency) if consistency is not None else None,
        is_serverless="EnableServerless" in caps,
        is_pppra_enabled=bool(getattr(acct, "enable_per_region_per_partition_autoscale", False) or False),
        capabilities=cap_names,
        backup_mode=_enum_text(backup_mode),
        continuous_backup_tier=_enum_text(continuous_tier),
        backup_migration_status=_enum_text(migration_status),
        backup_migration_target=_enum_text(migration_target),
        all_versions_and_deletes_enabled=(
            full_fidelity if isinstance(full_fidelity, bool) else None
        ),
    )


def offer_from_throughput(resource, *, database: str, container: str | None, level: str) -> ThroughputOffer:
    """Parse a ``ThroughputSettingsResource`` into a :class:`ThroughputOffer`.

    Pure (no I/O) so it can be unit-tested. Autoscale is identified by the presence of
    ``autoscale_settings.max_throughput``; otherwise it's manual ``throughput``.
    """
    auto = getattr(resource, "autoscale_settings", None)
    max_throughput = getattr(auto, "max_throughput", None) if auto is not None else None
    if max_throughput:
        return ThroughputOffer(
            database=database, container=container, level=level, mode="autoscale",
            provisioned_ru=float(max_throughput), minimum_ru=_f(getattr(resource, "minimum_throughput", None)),
        )
    return ThroughputOffer(
        database=database, container=container, level=level, mode="manual",
        provisioned_ru=float(resource.throughput), minimum_ru=_f(getattr(resource, "minimum_throughput", None)),
    )


class ArmProvider:
    """Control-plane reads for Cosmos DB (NoSQL API) throughput + inventory."""

    def __init__(self, credential: TokenCredential, subscription_id: str) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._client = CosmosDBManagementClient(credential, subscription_id)
        self._monitor = None  # lazily created (azure-mgmt-monitor) for Activity Log reads
        self._subscriptions = None  # lazily created (azure-mgmt-resource) for the subscription name
        self._subscription_name: str | None = None  # cached display name

    @property
    def credential(self) -> TokenCredential:
        """Credential shared with per-worker provider instances; SDK clients are not shared."""
        return self._credential

    @property
    def subscription_id(self) -> str:
        """Subscription id used when cloning ARM providers for parallel read workers."""
        return self._subscription_id

    def get_account(self, resource_group: str, account: str):
        """Read the account (control-plane). Used as a lightweight ARM read probe."""
        return self._client.database_accounts.get(resource_group, account)

    def get_subscription_name(self) -> str | None:
        """Subscription display name (an environment-classification signal). None if unavailable."""
        if self._subscription_name is None:
            try:
                from azure.mgmt.subscription import SubscriptionClient
                if self._subscriptions is None:
                    self._subscriptions = SubscriptionClient(self._credential)
                sub = self._subscriptions.subscriptions.get(self._subscription_id)
                self._subscription_name = getattr(sub, "display_name", None)
            except Exception:  # noqa: BLE001 - the name is an optional signal; degrade gracefully
                self._subscription_name = None
        return self._subscription_name

    def resolve_arm_region_names(self, configured_regions: tuple[str, ...]) -> tuple[str, ...]:
        """Resolve every account location to its canonical Retail API ``armRegionName``.

        Account locations commonly use display names (for example ``West US 3``), while Retail
        Prices keys records by canonical ARM names (``westus3``). Subscription location metadata is
        the authoritative mapping; an absent or ambiguous alias fails closed.
        """
        from azure.mgmt.subscription import SubscriptionClient

        if self._subscriptions is None:
            self._subscriptions = SubscriptionClient(self._credential)
        aliases: dict[str, set[str]] = {}
        for location in self._subscriptions.subscriptions.list_locations(self._subscription_id):
            canonical = str(getattr(location, "name", "") or "").casefold()
            if not canonical:
                continue
            for value in (
                getattr(location, "name", None),
                getattr(location, "display_name", None),
                getattr(location, "regional_display_name", None),
            ):
                if value:
                    aliases.setdefault(str(value).casefold(), set()).add(canonical)

        resolved: list[str] = []
        for configured in configured_regions:
            matches = aliases.get(str(configured).casefold(), set())
            if len(matches) != 1:
                raise ValueError(f"ARM region cannot be mapped uniquely: {configured!r}")
            resolved.append(next(iter(matches)))
        if len(set(resolved)) != len(resolved):
            raise ValueError("configured account regions map to duplicate ARM region names")
        return tuple(resolved)

    def get_account_config(self, resource_group: str, account: str) -> AccountConfig:
        """Account-level config/state (multi-region writes, regions, API kind) for account detections."""
        acct = self._client.database_accounts.get(resource_group, account)
        return account_config_from_arm(acct, subscription_name=self.get_subscription_name())

    def get_account_created_at(self, resource_group: str, account: str) -> datetime | None:
        """Account creation time from ARM ``systemData.createdAt`` (None if unavailable).

        A container can't be older than its account, so this is a correct (if coarse) age guard
        and the fallback when per-container age is unavailable (see ``get_container_created_at``).
        """
        acct = self._client.database_accounts.get(resource_group, account)
        system_data = getattr(acct, "system_data", None)
        return getattr(system_data, "created_at", None) if system_data else None

    def get_container_created_at(
        self, resource_group: str, account: str, database: str, container: str,
        *, lookback_days: int = 89,
    ) -> datetime | None:
        """Per-container creation time from the **Activity Log** (None if not found in retention).

        The Cosmos ARM container resource exposes no ``systemData``, so true per-container age
        comes from the control-plane Activity Log: the earliest ``.../containers/write`` event is
        the creation. Activity Log retention is ~90 days, so a container created earlier returns
        ``None`` — and the caller falls back to account age, which is *safe*: such a container is
        necessarily >90 days old, well past any age floor.

        Read-only (Activity Log query). ``lookback_days`` stays inside the ~90-day retention.
        """
        from azure.mgmt.monitor import MonitorManagementClient

        if self._monitor is None:
            self._monitor = MonitorManagementClient(self._credential, self._subscription_id)
        acct = self._client.database_accounts.get(resource_group, account)
        container_id = f"{acct.id}/sqlDatabases/{database}/containers/{container}"
        start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        flt = f"eventTimestamp ge '{start.isoformat()}' and resourceId eq '{container_id}'"

        earliest: datetime | None = None
        for ev in self._monitor.activity_logs.list(filter=flt):
            op = (getattr(ev.operation_name, "value", "") or "").lower()
            if op.endswith("/containers/write"):
                ts = ev.event_timestamp
                if ts is not None and (earliest is None or ts < earliest):
                    earliest = ts
        return earliest

    def get_container_offer(
        self, resource_group: str, account: str, database: str, container: str
    ) -> ThroughputOffer:
        """Authoritative offer for one container: its dedicated throughput, else its shared DB."""
        sql = self._client.sql_resources
        try:
            ct = sql.get_sql_container_throughput(resource_group, account, database, container)
            return offer_from_throughput(ct.resource, database=database, container=container, level="container")
        except ResourceNotFoundError:
            dbt = sql.get_sql_database_throughput(resource_group, account, database)
            return offer_from_throughput(dbt.resource, database=database, container=None, level="database")

    def list_offers(self, resource_group: str, account: str) -> list[ThroughputOffer]:
        """Enumerate every throughput offer in the account (shared DB pools + dedicated containers).

        Serverless accounts have no throughput offers: the throughput reads raise a ``BadRequest``
        ("Reading or replacing offers is not supported for serverless accounts"), which we treat as
        "no offer" → returns ``[]`` (serverless containers are diagnosed via :meth:`list_containers`
        + the DX-018 pass instead).
        """
        sql = self._client.sql_resources
        offers: list[ThroughputOffer] = []
        for db in sql.list_sql_databases(resource_group, account):
            db_name = db.name
            try:
                dbt = sql.get_sql_database_throughput(resource_group, account, db_name)
                offers.append(offer_from_throughput(dbt.resource, database=db_name, container=None, level="database"))
            except (ResourceNotFoundError, HttpResponseError) as exc:
                if not _is_no_offer_error(exc):
                    raise
                # no shared offer at the database level (dedicated containers) or serverless account
            for cont in sql.list_sql_containers(resource_group, account, db_name):
                try:
                    ct = sql.get_sql_container_throughput(resource_group, account, db_name, cont.name)
                    offers.append(
                        offer_from_throughput(ct.resource, database=db_name, container=cont.name, level="container")
                    )
                except (ResourceNotFoundError, HttpResponseError) as exc:
                    if not _is_no_offer_error(exc):
                        raise
                    continue  # draws from the shared DB pool, or a serverless container (no offer)
        return offers

    def list_containers(self, resource_group: str, account: str) -> list[tuple[str, str]]:
        """Enumerate every ``(database, container)`` in the account, regardless of throughput offer.

        Serverless containers have **no throughput offer** (so ``list_offers`` skips them), yet they
        still need diagnosing (DX-018 serverless throttling). This pure-inventory enumeration is the
        unit source for the serverless-container pass. Read-only (``list_*`` only).
        """
        sql = self._client.sql_resources
        pairs: list[tuple[str, str]] = []
        for db in sql.list_sql_databases(resource_group, account):
            for cont in sql.list_sql_containers(resource_group, account, db.name):
                pairs.append((db.name, cont.name))
        return pairs

    def list_container_indexing(self, resource_group: str, account: str) -> list[ContainerIndexing]:
        """Enumerate every container with its indexing policy (DX-024 inventory).

        Covers dedicated, shared-database and serverless containers alike — indexing cost applies
        regardless of throughput model. The container list response already carries
        ``resource.indexingPolicy``, so this is one ``list_*`` call per database. Read-only.
        """
        sql = self._client.sql_resources
        out: list[ContainerIndexing] = []
        for db in sql.list_sql_databases(resource_group, account):
            for cont in sql.list_sql_containers(resource_group, account, db.name):
                out.append(container_indexing_from_arm(db.name, cont))
        return out

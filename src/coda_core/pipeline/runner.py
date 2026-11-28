"""End-to-end diagnostic orchestrator: Select -> Detect -> Rollup -> Report (ADR-0007).

Ties the three scope layers together for one account:
  1. **Select** ARM-confirmed offers and their actual members, retaining inventory gaps.
  2. **Detect** — for each unit, run every applicable detection in the registry.
  3. **Rollup** — correlate within units, aggregate across the account.
  4. **Report** — return a structured :class:`DiagnosticReport`.
"""

from __future__ import annotations

import concurrent.futures
from collections import Counter, defaultdict
import logging
import os
import threading
import urllib.error
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from coda_core.detections import cross_partition_query as cpq
from coda_core.detections import indexing_cost as indexing
from coda_core.detections import logical_partition_storage as lps
from coda_core.detections import partition_merge as pm
from coda_core.detections import shared_throughput as sht
from coda_core.detections import uncontrolled_ingestion as ui
from coda_core.framework.cost_rate import (
    RATE_SCOPE_ACCOUNT,
    RATE_SCOPE_SUBSCRIPTION_FALLBACK,
    EffectiveRate,
    CostEstimateIssue,
    cost_estimate_issue,
    derive_effective_rate,
    throughput_meter,
)
from coda_core.pipeline.capabilities import (
    CAP_COST_MANAGEMENT,
    CAP_LA_DATAPLANE,
    CAP_LA_QUERYSTATS,
    CAP_LA_REQUEST_AGGREGATES,
    resolve_capabilities,
)
from coda_core.pipeline.context import (
    MODE_EVAL,
    MODE_PRODUCTION,
    AccountDetectionContext,
    DatabaseDetectionContext,
    DetectionContext,
    InventoryDetectionContext,
    ServerlessDetectionContext,
)
from coda_core.pipeline.registry import (
    ACCOUNT_REGISTRY,
    DATABASE_REGISTRY,
    INVENTORY_REGISTRY,
    REGISTRY,
    SERVERLESS_REGISTRY,
    _account_unit,
    _error_finding,
    run_account,
    run_container,
    run_database,
    run_inventory,
    run_serverless,
    threshold_status_for,
)
from coda_core.pipeline.report import DiagnosticReport, now_iso
from coda_core.pipeline.rollup import aggregate, compute_scope_provisioned_ru, correlate
from coda_core.providers.arm import ArmProvider, ResourceAge, account_config_from_arm
from coda_core.providers.diagnostic_settings import FanoutLogHistory
from coda_core.providers.indexing_batch import InvalidIndexingInventory, ProjectedReads, plan as plan_indexing
from coda_core.providers.monitor_cohort import COHORT_SIZE
from coda_core.providers.shared_offer import offer_request_counts
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import MetricSeries, TimeWindow
from coda_core.providers.cost_management import CostManagementProvider
from coda_core.providers.log_analytics import (
    CachingLogAnalyticsProvider,
    DataPlaneSource,
    LogAnalyticsProvider,
)
from coda_core.providers.retail_prices import RetailPricesProvider

DEFAULT_EVAL_HOURS = 24
# Window over which a CDB* table must show ≥1 row to count its capability as "configured". Wider than
# the analysis window so a *configured-but-quiet* account isn't falsely told to "enable category X"
# (matches diagnostic-log retention norms; the detector still judges sufficiency on its own window).
CAPABILITY_EXISTENCE_DAYS = 30
# Window for deriving the customer's effective $/RU/s rate from their amortized bill (ADR-0028). A
# recent ~month of billing is representative; the derivation is duration-independent (cost ÷ billed
# usage), so a partially-provisioned month still yields a correct unit price.
RATE_DERIVATION_DAYS = 30
DEFAULT_UNIT_CONCURRENCY = 4
UNIT_CONCURRENCY_ENV = "CODA_DIAGNOSE_UNIT_CONCURRENCY"
_LOGGER = logging.getLogger(__name__)


class _ThreadLocalUnitProviders:
    """Per-thread SDK clients for unit-level detection I/O.

    Single-account diagnosis now fans out database/container/serverless units concurrently. Azure SDK
    clients are not documented as thread-safe, so each worker thread gets fresh ARM and Metrics clients
    while sharing only the Entra credential (the same proven pattern used by ``scan()``).
    """

    def __init__(
        self,
        metrics: AzureMonitorMetricsProvider,
        arm: ArmProvider,
        la: LogAnalyticsProvider | None,
    ) -> None:
        self._base_metrics = metrics
        self._base_arm = arm
        self._la = la
        self._metrics_credential = getattr(metrics, "credential", None)
        self._arm_credential = getattr(arm, "credential", None)
        self._subscription_id = getattr(arm, "subscription_id", None)
        self._local = threading.local()

    @property
    def isolated(self) -> bool:
        """Only enable parallel SDK I/O when we can construct worker-owned clients."""
        return all(v is not None for v in (self._metrics_credential, self._arm_credential, self._subscription_id))

    def current(self) -> tuple[AzureMonitorMetricsProvider, ArmProvider, LogAnalyticsProvider | None]:
        """Return this worker thread's providers, falling back to supplied fakes in unit tests."""
        if not self.isolated:
            return self._base_metrics, self._base_arm, self._la
        providers = getattr(self._local, "providers", None)
        if providers is None:
            providers = (
                AzureMonitorMetricsProvider(self._metrics_credential,
                                            cooldown=getattr(self._base_metrics, "cooldown", None),
                                            budget=getattr(self._base_metrics, "budget", None)),
                ArmProvider(self._arm_credential, self._subscription_id),
                self._la,
            )
            self._local.providers = providers
        return providers


def _resolve_unit_concurrency(unit_concurrency: int | None) -> int:
    """Bound the per-unit worker count; defaults can be tuned without changing detection semantics."""
    raw = unit_concurrency
    if raw is None:
        env_value = os.environ.get(UNIT_CONCURRENCY_ENV)
        if env_value:
            try:
                raw = int(env_value)
            except ValueError:
                raw = DEFAULT_UNIT_CONCURRENCY
        else:
            raw = DEFAULT_UNIT_CONCURRENCY
    return max(1, int(raw))


def _ordered_parallel_map(items, worker, *, concurrency: int) -> list:
    """Run I/O-bound unit work concurrently and return results in input order.

    The previous serial loop's report order is part of the customer-facing contract. We therefore let
    workers complete out of order but store each result at its original index before flattening.
    """
    if not items:
        return []
    if concurrency <= 1 or len(items) == 1:
        return [worker(idx, item) for idx, item in enumerate(items)]
    sentinel = object()
    results = [sentinel] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrency, len(items))) as ex:
        fut_map = {ex.submit(worker, idx, item): idx for idx, item in enumerate(items)}
        for fut in concurrent.futures.as_completed(fut_map):
            results[fut_map[fut]] = fut.result()
    return results


def _run_metric_groups(items, cohort_key, axes, worker, providers, concurrency):
    """Process bounded, compatible ARM inventory groups; restore the original report ordering."""
    grouped = defaultdict(list)
    for i, item in enumerate(items):
        grouped[cohort_key(item)].append((i, item))
    stride = min(COHORT_SIZE, max(2, (len(items) + concurrency - 1) // concurrency))
    tasks = [(key[0], entries[start:start + stride]) for key, entries in grouped.items()
             for start in range(0, len(entries), stride)]

    def run_group(_, task):
        db, entries = task
        names, owners = axes([unit for _, unit in entries])
        provider, _, _ = providers.current()
        view = provider.for_cohort(db, names, owners)
        return [(i, worker(i, item, view)) for i, item in entries]

    ordered = [None] * len(items)
    for group in _ordered_parallel_map(tasks, run_group, concurrency=concurrency):
        for i, result in group:
            ordered[i] = result
    return ordered


def _group_rows(rows: list[dict]) -> dict[tuple[str, str], list[dict]]:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        key = (str(row.get("DatabaseName") or ""), str(row.get("CollectionName") or ""))
        grouped.setdefault(key, []).append(row)
    return grouped


def _prime_log_analytics_cache(
    la: CachingLogAnalyticsProvider | None,
    account_resource_id: str,
    container_offers,
    database_offers,
    run_now: datetime,
    caps,
) -> None:
    """Batch account-wide LA reads and seed exact per-detector cache keys.

    Detectors ask for their source-specific one-container/one-database KQL, but the shared cache
    can answer from a smaller number of batched
    account queries. Capability resolution has already established table availability over its longer
    existence window, so an empty analysis-window batch is cached as empty telemetry rather than
    reclassified as missing diagnostics. Any batch failure falls back to normal per-unit queries.
    """
    if la is None:
        return
    containers = [
        (offer.database, offer.container)
        for offer in container_offers
        if offer.container is not None
    ]
    if not containers and not database_offers:
        return

    source = caps.dataplane_source
    ingestion_window = ui.production_window(run_now)
    ingestion_span = (ingestion_window.start, ingestion_window.end)

    def _read(kql: str, span):
        """One account-wide LA read; rows or None on failure (prefetch is strictly best-effort)."""
        try:
            return la.query_resource(account_resource_id, kql, span)
        except Exception:  # noqa: BLE001 - prefetch is an optimization; detectors can still run
            return None

    # Overlap the independent account-wide LA reads instead of issuing them serially on the critical
    # path (they were ~5 sequential ~3s round-trips before workers even start). The caching provider is
    # thread-safe (ADR-0032), and the per-unit prime calls below run single-threaded on the main thread,
    # so cache keys, seeded rows, and detector semantics are byte-for-byte identical to the serial path.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        qs_span = None
        qs_fut = None
        if containers and caps.has(CAP_LA_QUERYSTATS) and caps.has(CAP_LA_DATAPLANE):
            query_window = cpq.production_window(run_now)
            qs_span = (query_window.start, query_window.end)
            qs_kql = cpq.fanout_batch_kql(containers, query_window)
            qs_fut = ex.submit(_read, qs_kql, qs_span)

        ingestion_futures = {}
        if containers and source is not None and caps.has(CAP_LA_REQUEST_AGGREGATES):
            for build in (ui.interval_kql, ui.burst_kql, ui.user_agent_kql):
                query = build(containers, source, ingestion_window, account_resource_id)
                ingestion_futures[build] = ex.submit(_read, query, ingestion_span)

        dbs = None
        shared_fut = None
        if database_offers and source is not None and caps.has(CAP_LA_REQUEST_AGGREGATES):
            dbs = [dbo.database for dbo in database_offers]
            data_window = sht.production_window(run_now, source)
            data_span = (data_window.start, data_window.end)
            shared_kql = sht.traffic_kql(dbs, source, data_window)
            shared_fut = ex.submit(_read, shared_kql, data_span)

        # Seed the exact per-unit cache keys from the batched results (main thread; order-independent).
        if qs_fut is not None:
            qs_raw = qs_fut.result()
            if qs_raw is not None:
                grouped = _group_rows(qs_raw)
                for db, container in containers:
                    rows = grouped.get((db, container), [])
                    la.prime_query_resource(
                        account_resource_id, cpq.query_shape_kql(db, container, query_window), qs_span, rows
                    )

        for build, future in ingestion_futures.items():
            rows = future.result()
            if rows is None:
                continue
            grouped = _group_rows(rows)
            if not grouped.keys() <= set(containers):
                continue  # Unattributed cohort rows cannot seed an empty/clean per-container result.
            for unit in containers:
                la.prime_query_resource(
                    account_resource_id, build([unit], source, ingestion_window, account_resource_id),
                    ingestion_span, grouped.get(unit, []),
                )

        if shared_fut is not None:
            shared_raw = shared_fut.result()
            if shared_raw is not None:
                by_db = defaultdict(list)
                for row in shared_raw:
                    by_db[row.get("DatabaseName")].append(row)
                for db in dbs:
                    la.prime_query_resource(
                        account_resource_id, sht.traffic_kql(db, source, data_window), data_span, by_db[db]
                    )


def _cost_query_issue(exc: Exception, query_scope: str) -> CostEstimateIssue:
    """Classify billing failures safely; retain the reason without changing fallback/retry policy."""
    status = exc.code if isinstance(exc, urllib.error.HTTPError) else getattr(exc, "status_code", None)
    status = status if type(status) is int and 100 <= status <= 599 else None
    reason = (
        "rate_limited" if status == 429 else
        "authentication" if status == 401 or type(exc).__name__ in {
            "ClientAuthenticationError", "CredentialUnavailableError",
        } else
        "access_denied" if status == 403 or isinstance(exc, PermissionError) else
        "timeout" if isinstance(exc, TimeoutError) or (
            isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError)
        ) else
        "service_unavailable" if status is not None and status >= 500 else "query_failed"
    )
    issue = cost_estimate_issue(reason, query_scope, http_status=status)
    _LOGGER.warning("Cost enrichment unavailable: %s (scope=%s)", issue.code, query_scope)
    return issue


def _derive_effective_rate(
    cost: CostManagementProvider | None, account_resource_id: str, run_now: datetime,
    caps, meter: str | None,
) -> tuple[EffectiveRate | None, CostEstimateIssue | None]:
    """Derive a customer-bill $/RU/s rate without masking account-query failures.

    The account-attributed amortized rate is preferred. A subscription-amortized rate is queried only
    after that account query succeeds but has no positive finite rate, which covers Azure billing
    attribution latency for newly provisioned accounts. An account-query exception fails closed
    immediately so an auth or transient failure is never hidden by a broader query (ADR-0051).
    Return the usable rate or one account-level explanation for why dollar enrichment is unavailable.
    """
    if cost is None or not caps.has(CAP_COST_MANAGEMENT):
        return None, cost_estimate_issue("not_configured", "not_queried")
    if meter is None:
        return None, cost_estimate_issue("unknown_billing_configuration", "not_queried")
    start = (run_now - timedelta(days=RATE_DERIVATION_DAYS)).date()
    try:
        account_cost = cost.cosmos_throughput_cost(
            start,
            run_now.date(),
            resource_id=account_resource_id,
            meter=meter,
        )
        account_rate = derive_effective_rate(
            account_cost.cost,
            account_cost.usage,
            account_cost.currency,
            rate_scope=RATE_SCOPE_ACCOUNT,
            meters=account_cost.meters,
        )
    except Exception as exc:  # noqa: BLE001 - retain a safe reason; capacity diagnosis remains valid
        return None, _cost_query_issue(exc, RATE_SCOPE_ACCOUNT)
    if account_rate is not None and account_rate.basis["meters"] == [meter]:
        return account_rate, None
    try:
        subscription_cost = cost.cosmos_throughput_cost(start, run_now.date(), meter=meter)
        subscription_rate = derive_effective_rate(
            subscription_cost.cost,
            subscription_cost.usage,
            subscription_cost.currency,
            rate_scope=RATE_SCOPE_SUBSCRIPTION_FALLBACK,
            meters=subscription_cost.meters,
        )
    except Exception as exc:  # noqa: BLE001 - fallback failure remains visible and capacity-only
        return None, _cost_query_issue(exc, RATE_SCOPE_SUBSCRIPTION_FALLBACK)
    return (
        (subscription_rate, None) if subscription_rate is not None and subscription_rate.basis["meters"] == [meter]
        else (None, cost_estimate_issue("no_usable_rate", RATE_SCOPE_SUBSCRIPTION_FALLBACK))
    )


def default_eval_window(now: datetime | None = None, hours: int = DEFAULT_EVAL_HOURS) -> TimeWindow:
    """Build source-compatible relative eval windows without moving an explicitly pinned end."""
    anchor = now if now is not None else DataPlaneSource.FIVE_MINUTE.anchor(datetime.now(timezone.utc))
    return TimeWindow(anchor - timedelta(hours=hours), anchor, timedelta(hours=1))


def _count_scanned_resources(
    container_offers: list,
    database_offers: list,
    serverless_units: int,
) -> int:
    """Count each account, shared database, and container inspected by a diagnosis exactly once."""
    return 1 + len(database_offers) + len(container_offers) + serverless_units


def run_diagnostics(
    metrics: AzureMonitorMetricsProvider,
    arm: ArmProvider,
    resource_group: str,
    account: str,
    *,
    mode: str,
    eval_window: TimeWindow | None = None,
    la: LogAnalyticsProvider | None = None,
    cost: CostManagementProvider | None = None,
    retail_prices: RetailPricesProvider | None = None,
    unit_concurrency: int | None = None,
) -> DiagnosticReport:
    """Run the full pipeline for one account and return its report.

    ``la`` enables database/container LA-backed detections. ``retail_prices`` is the unauthenticated,
    read-only DX-019 list-price enrichment; its absence or failure never suppresses the ARM finding.
    ``unit_concurrency`` bounds parallel work; ordering is restored before rollup.
    """
    # The executor starts threads only on submit. Its owner joins them even if another pass raises
    # before the optional age lookups are collected.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as age_pool:
        return _run_diagnostics(metrics, arm, resource_group, account, mode=mode, eval_window=eval_window,
                                la=la, cost=cost, retail_prices=retail_prices,
                                unit_concurrency=unit_concurrency, age_pool=age_pool)


def _run_diagnostics(
    metrics: AzureMonitorMetricsProvider, arm: ArmProvider, resource_group: str, account: str,
    *, mode: str, eval_window: TimeWindow | None, la: LogAnalyticsProvider | None,
    cost: CostManagementProvider | None, retail_prices: RetailPricesProvider | None,
    unit_concurrency: int | None, age_pool: concurrent.futures.ThreadPoolExecutor,
) -> DiagnosticReport:
    """Evaluate the report, overlapping optional resource-age reads with independent checks."""
    if callable(getattr(type(metrics), "for_report", None)):
        metrics = metrics.for_report()
    inventory = arm.inspect_offers(resource_group, account)
    offers = inventory.offers
    container_offers = [o for o in offers if o.level == "container"]
    database_offers = [o for o in offers if o.level == "database"]
    acct = arm.get_account(resource_group, account)
    account_resource_id = acct.id
    account_config = account_config_from_arm(acct)
    scope_provisioned_ru = None if inventory.issues else compute_scope_provisioned_ru(offers)
    run_now = datetime.now(timezone.utc)          # single per-run anchor (stable LA cache keys)
    window = eval_window or default_eval_window(now=run_now)
    unit_concurrency = _resolve_unit_concurrency(unit_concurrency)
    # Memoize Log Analytics per run: DX-002/DX-007 issue the same fan-out KQL, while the data-plane
    # detectors share account-wide batches that are projected into their per-resource query keys.
    if la is not None:
        la_credential = getattr(la, "credential", None)
        la_factory = (lambda: LogAnalyticsProvider(la_credential)) if la_credential is not None else None
        la = CachingLogAnalyticsProvider(la, inner_factory=la_factory)
    worker_providers = _ThreadLocalUnitProviders(metrics, arm, la)
    # Only look for creation events if the resource's own ARM record cannot prove the age floor.
    ages = dict(inventory.ages)
    age_errors = {}
    _created_futs = {}
    if mode == MODE_PRODUCTION:
        _age_targets = []
        for o in offers:
            age = ages.get((o.database, o.container), ResourceAge())
            floor = max((a.minimum_age for a in REGISTRY if a.minimum_age and a.applies(o)),
                        default=None)
            anchor = run_now.replace(minute=0, second=0, microsecond=0)
            if floor and not age.created and (not age.existed_by or anchor - age.existed_by < floor):
                _age_targets.append(o)
        if _age_targets:
            def _fetch_created(off):
                _, warm_arm, _ = worker_providers.current()
                rid = f"{account_resource_id}/sqlDatabases/{off.database}"
                return warm_arm.resource_created_at(
                    f"{rid}/containers/{off.container}" if off.container else rid)

            for _off in _age_targets:
                _created_futs[(_off.database, _off.container)] = age_pool.submit(_fetch_created, _off)
    # Resolve capabilities ONCE per run (single source of truth for gating). Log Analytics is probed at
    # table granularity over a 30-day existence window so each LA detection gates on the exact category
    # it needs, with a category-precise "enable X" message instead of a silent clean result.
    cap_span = (run_now - timedelta(days=CAPABILITY_EXISTENCE_DAYS), run_now)
    caps = resolve_capabilities(
        la=la, account_resource_id=account_resource_id, span=cap_span,
        cost_available=cost is not None,
    )
    fanout_history = None
    need_fanout = (la is not None and (container_offers or account_config.is_serverless)
                   and caps.has(CAP_LA_QUERYSTATS) and caps.has(CAP_LA_DATAPLANE))
    need_keys = bool(container_offers) and any(a.detection_id == "DX-015" for a in REGISTRY)
    key_export = "unknown"
    if need_keys or need_fanout:
        try:
            exports = arm.diagnostic_log_exports(account_resource_id)
            if need_keys:
                key_export = exports[lps.TABLE].status
            if need_fanout:
                fanout_history = FanoutLogHistory.from_exports(exports)
        except Exception as exc:  # noqa: BLE001 - optional settings evidence; metrics stay independent
            fanout_history = FanoutLogHistory(None, f"Diagnostic setting read failed: {type(exc).__name__}")
    if eval_window is None and caps.dataplane_source is DataPlaneSource.FIVE_MINUTE:
        window = default_eval_window(now=caps.dataplane_source.anchor(run_now))
    logical_storage = {}
    if need_keys:
        log_window = window if mode == MODE_EVAL else TimeWindow(run_now-timedelta(days=7), run_now)
        units = {(o.database, o.container): ages.get((o.database, o.container), ResourceAge()).created
                 for o in container_offers if o.container is not None}
        logical_storage = lps.collect(la, account_resource_id, key_export, log_window, units)
    # Derive the customer's effective $/RU/s rate once per run from their amortized bill. Account rows
    # are preferred; subscription rows are a provenance-labelled billing-latency fallback (ADR-0051).
    # None means bill-derived savings findings stay capacity-only.
    effective_rate, cost_issue = _derive_effective_rate(cost, account_resource_id, run_now, caps,
                                                       throughput_meter(account_config))
    _prime_log_analytics_cache(la, account_resource_id, container_offers, database_offers, run_now, caps)

    findings = []
    use_cohorts = callable(getattr(type(metrics), "for_cohort", None))
    account_metrics = metrics.for_cohort("") if use_cohorts else metrics
    # Account-scoped detections (config/state) run once for the account.
    acct_ctx = AccountDetectionContext(
        metrics=account_metrics, account=account, account_resource_id=account_resource_id,
        config=account_config, mode=mode, eval_window=window, now=run_now,
        scope_provisioned_ru=scope_provisioned_ru, resource_group=resource_group, arm=arm,
        retail_prices=retail_prices, throughput_offers=tuple(offers), la=la,
        effective_rate=effective_rate,
        dataplane_source=caps.dataplane_source,
        dataplane_error=caps.probe_error_for(frozenset({CAP_LA_REQUEST_AGGREGATES})),
        inventory_issues=inventory.issues, cost=cost,
    )
    for acct_adapter in ACCOUNT_REGISTRY:
        findings.append(run_account(acct_adapter, acct_ctx, caps))

    # Database-scoped detections (shared-throughput databases) — LA-backed (DX-003). Always iterate so
    # a customer without Log Analytics gets an explicit "enable diagnostic settings" finding per shared
    # DB (the capability layer gates each one) instead of a silent skip.
    def _run_database_unit(_idx: int, dbo) -> list:
        _, _, worker_la = worker_providers.current()
        db_ctx = DatabaseDetectionContext(
            la=worker_la, account=account, account_resource_id=account_resource_id,
            database=dbo.database, shared_ru=dbo.provisioned_ru, mode=mode, eval_window=window,
            now=run_now,
            dataplane_source=caps.dataplane_source,
            pool_members=inventory.pools.get(dbo.database),
        )
        unit_findings = []
        for db_adapter in DATABASE_REGISTRY:
            unit_findings.append(run_database(db_adapter, db_ctx, caps))
        return unit_findings

    for unit_findings in _ordered_parallel_map(
        database_offers, _run_database_unit, concurrency=unit_concurrency
    ):
        findings.extend(unit_findings)

    # Serverless containers have no throughput offer, so the container loop below never sees them.
    # Diagnose them on a dedicated pass when the account is serverless (DX-018 serverless throttling).
    serverless_units = 0
    if account_config.is_serverless:
        serverless_containers = arm.list_containers(resource_group, account)
        serverless_units = len(serverless_containers)

        def _run_serverless_unit(_idx: int, unit: tuple[str, str], projected=None) -> list:
            db_name, container_name = unit
            worker_metrics, _, worker_la = worker_providers.current()
            age = ages.get(unit, ResourceAge())
            sls_ctx = ServerlessDetectionContext(
                metrics=projected or worker_metrics, account=account, account_resource_id=account_resource_id,
                database=db_name, container=container_name, mode=mode, eval_window=window,
                now=run_now, la=worker_la,
                resource_created_at=age.created, resource_existed_by=age.existed_by, fanout_log_history=fanout_history,
            )
            unit_findings = []
            for sls_adapter in SERVERLESS_REGISTRY:
                unit_findings.append(run_serverless(sls_adapter, sls_ctx, caps))
            return unit_findings

        if use_cohorts:
            sls_results = _run_metric_groups(
                serverless_containers, lambda u: (u[0],), lambda rows: ([u[1] for u in rows], []),
                _run_serverless_unit, worker_providers, unit_concurrency)
        else:
            sls_results = _ordered_parallel_map(serverless_containers, _run_serverless_unit,
                                                concurrency=unit_concurrency)
        for unit_findings in sls_results:
            findings.extend(unit_findings)

    storage_peaks = {}

    def _run_container_unit(_idx: int, offer, projected=None) -> list:
        worker_metrics, _, worker_la = worker_providers.current()
        if projected is not None:
            worker_metrics = projected
        key = (offer.database, offer.container)
        age = ages.get(key, ResourceAge())
        members = inventory.pools.get(offer.database) if offer.level == "database" else None
        ctx = DetectionContext(
            metrics=worker_metrics, account=account, account_resource_id=account_resource_id,
            offer=offer, mode=mode, eval_window=window, now=run_now,
            resource_created_at=age.created, resource_existed_by=age.existed_by,
            age_read_error=age_errors.get(key), scope_provisioned_ru=scope_provisioned_ru,
            pool_members=members,
            read_counts=offer_request_counts(worker_metrics, account_resource_id, offer.database,
                                             offer.container, members),
            la=worker_la, effective_rate=effective_rate,
            dataplane_source=caps.dataplane_source,
            account_config=account_config,
            storage_peak=storage_peaks.get(key),
            fanout_log_history=fanout_history,
            logical_storage=logical_storage.get(key),
        )
        unit_findings = []
        for adapter in REGISTRY:
            if adapter.applies(offer):
                unit_findings.append(run_container(adapter, ctx, caps))
        return unit_findings

    # Shared-throughput DATABASE offers also run the metrics-based detectors at database scope
    # (DX-001/004/005/006/011 — idle/over/under-provisioning, hot partition; see _is_metrics_scoped).
    # They additionally run the LA-backed DX-003 in the database pass above.
    # All-container inventory pass (DX-024 indexing cost): every container regardless of throughput
    # model, enumerated once from ARM with its indexing policy. An enumeration failure degrades to one
    # account-level abstention per inventory detection rather than aborting the run.
    inventory_tail = []
    if INVENTORY_REGISTRY:
        try:
            indexing_inventory = arm.list_container_indexing(resource_group, account)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully; never abort the run
            indexing_inventory = []
            for inv_adapter in INVENTORY_REGISTRY:
                inventory_tail.append(_error_finding(
                    inv_adapter.detection_id, inv_adapter.title, _account_unit(acct_ctx), exc,
                ))

        def _run_inventory_unit(_idx: int, cont, projected: ProjectedReads | None = None) -> list:
            worker_metrics, _, _ = worker_providers.current()
            inv_ctx = InventoryDetectionContext(
                metrics=worker_metrics, account=account, account_resource_id=account_resource_id,
                container=cont, mode=mode, eval_window=window, now=run_now,
            )
            return [run_inventory(a, replace(inv_ctx, metrics=projected)
                                  if projected is not None and a.detection_id == "DX-024" else inv_ctx, caps)
                    for a in INVENTORY_REGISTRY]

        index_window = window if mode == MODE_EVAL else indexing.production_window(run_now)
        if (callable(make_plan := getattr(metrics, "indexing_plan", None)) and indexing_inventory
                and index_window.end - index_window.start <= 72 * index_window.granularity
                and any(a.detection_id == "DX-024" and not caps.missing(a.requires) for a in INVENTORY_REGISTRY)):
            worker_provider = (lambda: worker_providers.current()[0]) if worker_providers.isolated else None
            reader = make_plan(account_resource_id, index_window, worker_provider=worker_provider)
            units = {(c.database, c.container): (i, c) for i, c in enumerate(indexing_inventory)}
            counts = Counter((c.database, c.container) for c in indexing_inventory)
            valid, ordered = [], {}
            for i, c in enumerate(indexing_inventory):
                if counts[c.database, c.container] == 1 and all(v and v != "*" for v in (c.database, c.container)):
                    valid.append(c)
                else:
                    ordered[i] = _run_inventory_unit(i, c, ProjectedReads.unavailable(
                        account_resource_id, index_window, c.database, (c.container,),
                        "Incomplete indexing inventory: invalid or duplicate container identity",
                        error_type=InvalidIndexingInventory))
            for batch, projection in reader.projections(plan_indexing(valid), unit_concurrency):
                for name in batch.containers:
                    i, container = units[batch.database, name]
                    ordered[i] = _run_inventory_unit(i, container, projection)
                    if use_cohorts and index_window == pm.recent_window(run_now):
                        cell = projection.cells.get((name, "DataUsage"))
                        if isinstance(cell, MetricSeries) and (peak := pm.measured_storage_peak(cell.values())) is not None:
                            storage_peaks[batch.database, name] = peak
            inventory_results = [ordered[i] for i in sorted(ordered)]
        else:
            inventory_results = _ordered_parallel_map(
                indexing_inventory, _run_inventory_unit, concurrency=unit_concurrency)
        for unit_findings in inventory_results:
            inventory_tail.extend(unit_findings)

    # Indexing does not depend on age; let its Monitor reads overlap pending ARM lookups.
    for _key, _fut in _created_futs.items():
        try:
            created = _fut.result()
        except Exception as exc:  # noqa: BLE001 - isolate optional SDK/decoding failures per resource
            age_errors[_key] = type(exc).__name__
        else:
            ages[_key] = replace(ages.get(_key, ResourceAge()), created=created)

    metrics_offers = container_offers + database_offers
    if use_cohorts:
        floors = sorted({a.minimum_age for a in REGISTRY if a.minimum_age})

        def cohort_key(o):
            """Never speculate across an age, mode, ownership or missing-evidence boundary."""
            age = ages.get((o.database, o.container), ResourceAge())
            since = age.created or age.existed_by
            anchor = run_now.replace(minute=0, second=0, microsecond=0)
            # Both anchors matter at a floor boundary (closed-hour and present-tense checks).
            bands = () if mode == MODE_EVAL else tuple(
                bool(since and t - since >= floor) for t in (anchor, run_now) for floor in floors)
            return o.database, o.mode, o.level, bands

        def axes(rows):
            first = rows[0]
            if first.container is None:
                pool = inventory.pools.get(first.database)
                return (pool.shared if pool and not pool.unresolved else ()), ()
            return [o.container for o in rows], [o.owner_rid for o in rows if o.owner_rid]

        offer_results = _run_metric_groups(metrics_offers, cohort_key, axes, _run_container_unit,
                                           worker_providers, unit_concurrency)
    else:
        offer_results = _ordered_parallel_map(metrics_offers, _run_container_unit, concurrency=unit_concurrency)
    for unit_findings in offer_results:
        findings.extend(unit_findings)
    findings.extend(inventory_tail)

    findings = correlate(findings)
    # Honesty policy (single source of truth): stamp each finding's threshold_status by whether the
    # detection's cutoffs are fleet-grounded vs still a proposal — so the report never overclaims.
    findings = [replace(f, threshold_status=threshold_status_for(f.detection_id)) for f in findings]
    summary = aggregate(
        findings,
        scope_provisioned_ru,
        units_scanned=_count_scanned_resources(
            container_offers,
            database_offers,
            serverless_units,
        ),
    )
    return DiagnosticReport(
        account=account, resource_group=resource_group, mode=mode,
        generated_at=now_iso(), summary=summary, findings=findings,
        account_resource_id=account_resource_id,
        account_endpoint=getattr(acct, "document_endpoint", None),
        cost_estimate_issue=cost_issue,
        inventory_issues=inventory.issues,
    )


__all__ = ["run_diagnostics", "default_eval_window", "MODE_EVAL"]

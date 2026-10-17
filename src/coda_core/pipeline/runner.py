"""End-to-end diagnostic orchestrator: Select -> Detect -> Rollup -> Report (ADR-0007).

Ties the three scope layers together for one account:
  1. **Select** every throughput offer (``ArmProvider.list_offers``); container-level offers are
     the units detections run on (shared-DB pools and serverless are future: DX-003 / DX-014).
  2. **Detect** — for each unit, run every applicable detection in the registry.
  3. **Rollup** — correlate within units, aggregate across the account.
  4. **Report** — return a structured :class:`DiagnosticReport`.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import threading
import urllib.error
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from coda_core.detections import cross_partition_query as cpq
from coda_core.detections import shared_throughput as sht
from coda_core.detections import uncontrolled_ingestion as ui
from coda_core.framework.cost_rate import (
    RATE_SCOPE_ACCOUNT,
    RATE_SCOPE_SUBSCRIPTION_FALLBACK,
    EffectiveRate,
    CostEstimateIssue,
    cost_estimate_issue,
    derive_effective_rate,
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
    ServerlessDetectionContext,
)
from coda_core.pipeline.registry import (
    ACCOUNT_REGISTRY,
    DATABASE_REGISTRY,
    REGISTRY,
    SERVERLESS_REGISTRY,
    run_account,
    run_container,
    run_database,
    run_serverless,
    threshold_status_for,
)
from coda_core.pipeline.report import DiagnosticReport, now_iso
from coda_core.pipeline.rollup import aggregate, compute_scope_provisioned_ru, correlate
from coda_core.providers.arm import ArmProvider, account_config_from_arm
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.base import TimeWindow
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

    def current(self) -> tuple[AzureMonitorMetricsProvider, ArmProvider, LogAnalyticsProvider | None]:
        """Return this worker thread's providers, falling back to supplied fakes in unit tests."""
        if (
            self._metrics_credential is None
            or self._arm_credential is None
            or self._subscription_id is None
        ):
            return self._base_metrics, self._base_arm, self._la
        providers = getattr(self._local, "providers", None)
        if providers is None:
            providers = (
                AzureMonitorMetricsProvider(self._metrics_credential),
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


def _kql_literal(value: str) -> str:
    """Quote a Cosmos name for KQL using the detectors' existing quote-stripping convention."""
    return "'" + value.replace("'", "") + "'"


def _container_predicate(units: list[tuple[str, str]]) -> str:
    """KQL predicate matching the exact account containers being diagnosed."""
    return " or ".join(
        f"(DatabaseName == {_kql_literal(db)} and CollectionName == {_kql_literal(container)})"
        for db, container in units
    )


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
    data_window = (
        ui.production_window(run_now, source) if source is not None
        else ui.production_window(run_now)
    )
    data_span = (data_window.start, data_window.end)
    predicate = _container_predicate(containers) if containers else ""
    writes = ", ".join(f"'{w}'" for w in ui.WRITE_OPS)

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
            qs_kql = (
                "CDBQueryRuntimeStatistics "
                f"| where {predicate} "
                "| project DatabaseName, CollectionName, ActivityId, CorrelatedActivityId, "
                "QueryText, PartitionKeyRangeId "
                "| join kind=leftouter ("
                "CDBDataPlaneRequests "
                f"| where {predicate} "
                "| summarize ru = sum(RequestCharge) by ActivityId"
                ") on ActivityId "
                "| summarize partitionsHit = dcount(PartitionKeyRangeId), queryRU = sum(ru) "
                "by DatabaseName, CollectionName, CorrelatedActivityId, QueryText "
                "| summarize executions = count(), avgFanout = avg(partitionsHit), "
                "maxFanout = max(partitionsHit), avgRU = avg(queryRU) "
                "by DatabaseName, CollectionName, QueryText"
            )
            qs_fut = ex.submit(_read, qs_kql, qs_span)

        dp_futs = None
        if containers and source is not None and caps.has(CAP_LA_REQUEST_AGGREGATES):
            agg_kql = (
                source.query_table(data_window)
                + f"| where {predicate} "
                f"| summarize totalRu = sum({source.charge}), "
                f"writeRu = sumif({source.charge}, OperationName in ({writes})), "
                f"reqs = {source.count}, throttles = {source.count_if('StatusCode == 429')}"
                f"{source.invalid_rows} "
                "by DatabaseName, CollectionName"
            )
            burst_kql = (
                source.query_table(data_window)
                + f"| where ({predicate}) and OperationName in ({writes}) "
                f"| summarize ru = sum({source.charge}) by DatabaseName, CollectionName, "
                f"bin(TimeGenerated, {source.burst_interval}) "
                "| summarize peak = max(ru), avg = avg(ru) by DatabaseName, CollectionName"
            )
            ua_kql = (
                source.query_table(data_window)
                + f"| where ({predicate}) and OperationName in ({writes}) "
                f"| summarize n = {source.count} by DatabaseName, CollectionName, UserAgent "
                "| summarize arg_max(n, UserAgent) by DatabaseName, CollectionName"
            )
            dp_futs = {
                "agg": ex.submit(_read, agg_kql, data_span),
                "burst": ex.submit(_read, burst_kql, data_span),
                "ua": ex.submit(_read, ua_kql, data_span),
            }

        dbs = None
        shared_fut = None
        if database_offers and source is not None and caps.has(CAP_LA_REQUEST_AGGREGATES):
            dbs = [dbo.database for dbo in database_offers]
            db_literals = ", ".join(_kql_literal(db) for db in dbs)
            shared_kql = (
                source.query_table(data_window)
                + f"| where DatabaseName in ({db_literals}) and isnotempty(CollectionName) "
                f"| summarize requests = {source.count}, "
                f"throttled = {source.count_if('StatusCode == 429')}, "
                f"ru = sum({source.charge}){source.invalid_rows} by DatabaseName, CollectionName"
            )
            shared_fut = ex.submit(_read, shared_kql, data_span)

        # Seed the exact per-unit cache keys from the batched results (main thread; order-independent).
        if qs_fut is not None:
            qs_raw = qs_fut.result()
            if qs_raw is not None:
                grouped = _group_rows(qs_raw)
                for db, container in containers:
                    rows = grouped.get((db, container), [])
                    rows = sorted(rows, key=lambda r: r.get("executions") or 0, reverse=True)[:200]
                    la.prime_query_resource(
                        account_resource_id, cpq.query_shape_kql(db, container), qs_span, rows
                    )

        if dp_futs is not None:
            agg_raw = dp_futs["agg"].result()
            burst_raw = dp_futs["burst"].result()
            ua_raw = dp_futs["ua"].result()
            if agg_raw is not None and burst_raw is not None and ua_raw is not None:
                agg_by_unit = _group_rows(agg_raw)
                burst_by_unit = _group_rows(burst_raw)
                ua_by_unit = _group_rows(ua_raw)
                for db, container in containers:
                    zero = [{"totalRu": 0.0, "writeRu": 0.0, "reqs": 0, "throttles": 0}]
                    if source.invalid_rows:
                        zero[0]["invalid_rows"] = 0
                    la.prime_query_resource(
                        account_resource_id, ui.aggregate_kql(db, container, source, data_window), data_span,
                        agg_by_unit.get((db, container), zero),
                    )
                    la.prime_query_resource(
                        account_resource_id, ui.burst_kql(db, container, source, data_window), data_span,
                        burst_by_unit.get((db, container), []),
                    )
                    la.prime_query_resource(
                        account_resource_id, ui.user_agent_kql(db, container, source, data_window), data_span,
                        ua_by_unit.get((db, container), []),
                    )

        if shared_fut is not None:
            shared_raw = shared_fut.result()
            if shared_raw is not None:
                grouped = _group_rows(shared_raw)
                for db in dbs:
                    rows = []
                    for (row_db, _), group in grouped.items():
                        if row_db == db:
                            rows.extend(group)
                    la.prime_query_resource(
                        account_resource_id, sht.traffic_kql(db, source, data_window), data_span, rows
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
    caps,
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
    start = (run_now - timedelta(days=RATE_DERIVATION_DAYS)).date()
    try:
        account_cost = cost.cosmos_throughput_cost(
            start,
            run_now.date(),
            resource_id=account_resource_id,
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
    if account_rate is not None:
        return account_rate, None
    try:
        subscription_cost = cost.cosmos_throughput_cost(start, run_now.date())
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
        (subscription_rate, None) if subscription_rate is not None
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
    offers = arm.list_offers(resource_group, account)
    container_offers = [o for o in offers if o.level == "container"]
    database_offers = [o for o in offers if o.level == "database"]
    acct = arm.get_account(resource_group, account)
    account_resource_id = acct.id
    account_created_at = arm.get_account_created_at(resource_group, account)
    account_config = account_config_from_arm(acct)
    scope_provisioned_ru = compute_scope_provisioned_ru(offers)
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
    # Prefetch per-container creation times (Activity Log; ~4s each) concurrently and overlap them with
    # capability resolution + LA priming + the database/serverless passes below, so the container loop
    # never blocks on them. Production only (eval disables the age guard); values and the account-age
    # fallback are unchanged, so findings are identical to fetching them inline.
    container_created_at: dict[tuple[str, str], datetime | None] = {}
    _created_ex = None
    _created_futs: dict[tuple[str, str], object] = {}
    if mode == MODE_PRODUCTION:
        _age_targets = [o for o in container_offers if o.container]
        if _age_targets:
            _created_ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(len(_age_targets), 8))

            def _fetch_created(off):
                _, warm_arm, _ = worker_providers.current()
                return warm_arm.get_container_created_at(
                    resource_group, account, off.database, off.container
                )

            for _off in _age_targets:
                _created_futs[(_off.database, _off.container)] = _created_ex.submit(_fetch_created, _off)
    # Resolve capabilities ONCE per run (single source of truth for gating). Log Analytics is probed at
    # table granularity over a 30-day existence window so each LA detection gates on the exact category
    # it needs, with a category-precise "enable X" message instead of a silent clean result.
    cap_span = (run_now - timedelta(days=CAPABILITY_EXISTENCE_DAYS), run_now)
    caps = resolve_capabilities(
        la=la, account_resource_id=account_resource_id, span=cap_span,
        cost_available=cost is not None,
    )
    if eval_window is None and caps.dataplane_source is DataPlaneSource.FIVE_MINUTE:
        window = default_eval_window(now=caps.dataplane_source.anchor(run_now))
    # Derive the customer's effective $/RU/s rate once per run from their amortized bill. Account rows
    # are preferred; subscription rows are a provenance-labelled billing-latency fallback (ADR-0051).
    # None means bill-derived savings findings stay capacity-only.
    effective_rate, cost_issue = _derive_effective_rate(cost, account_resource_id, run_now, caps)
    _prime_log_analytics_cache(la, account_resource_id, container_offers, database_offers, run_now, caps)

    findings = []
    # Account-scoped detections (config/state) run once for the account.
    acct_ctx = AccountDetectionContext(
        metrics=metrics, account=account, account_resource_id=account_resource_id,
        config=account_config, mode=mode, eval_window=window, now=run_now,
        scope_provisioned_ru=scope_provisioned_ru, resource_group=resource_group, arm=arm,
        retail_prices=retail_prices, throughput_offers=tuple(offers), la=la,
        effective_rate=effective_rate,
        dataplane_source=caps.dataplane_source,
        dataplane_error=caps.probe_error_for(frozenset({CAP_LA_REQUEST_AGGREGATES})),
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

        def _run_serverless_unit(_idx: int, unit: tuple[str, str]) -> list:
            db_name, container_name = unit
            worker_metrics, _, worker_la = worker_providers.current()
            sls_ctx = ServerlessDetectionContext(
                metrics=worker_metrics, account=account, account_resource_id=account_resource_id,
                database=db_name, container=container_name, mode=mode, eval_window=window,
                now=run_now, la=worker_la,
            )
            unit_findings = []
            for sls_adapter in SERVERLESS_REGISTRY:
                unit_findings.append(run_serverless(sls_adapter, sls_ctx, caps))
            return unit_findings

        for unit_findings in _ordered_parallel_map(
            serverless_containers, _run_serverless_unit, concurrency=unit_concurrency
        ):
            findings.extend(unit_findings)

    def _run_container_unit(_idx: int, offer) -> list:
        worker_metrics, _, worker_la = worker_providers.current()
        # Per-container age (Activity Log) when judging in production; falls back to account age.
        # Prefetched concurrently above, so this is a dict lookup rather than a blocking call here.
        if mode == MODE_PRODUCTION and offer.container:
            resource_created_at = (
                container_created_at.get((offer.database, offer.container)) or account_created_at
            )
        else:
            resource_created_at = account_created_at
        ctx = DetectionContext(
            metrics=worker_metrics, account=account, account_resource_id=account_resource_id,
            offer=offer, mode=mode, eval_window=window, now=run_now,
            resource_created_at=resource_created_at, scope_provisioned_ru=scope_provisioned_ru,
            la=worker_la, effective_rate=effective_rate,
            dataplane_source=caps.dataplane_source,
        )
        unit_findings = []
        for adapter in REGISTRY:
            if adapter.applies(offer):
                unit_findings.append(run_container(adapter, ctx, caps))
        return unit_findings

    # Join the concurrent creation-time prefetch (started up-front, overlapped with the passes above).
    for _key, _fut in _created_futs.items():
        try:
            container_created_at[_key] = _fut.result()
        except Exception:  # noqa: BLE001 - age lookup failure falls back to account age
            container_created_at[_key] = None
    if _created_ex is not None:
        _created_ex.shutdown(wait=True)

    # Shared-throughput DATABASE offers also run the metrics-based detectors at database scope
    # (DX-001/004/005/006/011 — idle/over/under-provisioning, hot partition; see _is_metrics_scoped).
    # They additionally run the LA-backed DX-003 in the database pass above.
    metrics_offers = container_offers + database_offers
    for unit_findings in _ordered_parallel_map(
        metrics_offers, _run_container_unit, concurrency=unit_concurrency
    ):
        findings.extend(unit_findings)

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
    )


__all__ = ["run_diagnostics", "default_eval_window", "MODE_EVAL"]

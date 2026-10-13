"""Log Analytics provider.

Runs KQL against a customer's Cosmos DB resource logs (the ``CDB*`` resource-specific diagnostic
tables) and returns rows. Auth is Entra ID only.

CODA queries **by the Cosmos account's ARM resource id** (``query_resource``) rather than a workspace
GUID: the service resolves whichever workspace the account's diagnostic settings export to, so CODA
needs no workspace discovery and degrades cleanly when no workspace is configured (the query simply
returns no ``CDB*`` rows — see ``cdb_logs_available``).

Retention here is customer-controlled (default 30 days, configurable up to ~2 years), which is why
CODA prefers Log-Analytics-backed detections for durable fixtures.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime
from typing import Any, TypeVar

from azure.core.credentials import TokenCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

_T = TypeVar("_T")


def _error_text(value: object) -> str:
    """Flatten SDK error details without discarding nested semantic messages."""
    if isinstance(value, dict):
        return " ".join(
            part for item in value.values() if (part := _error_text(item))
        )
    if isinstance(value, (list, tuple)):
        return " ".join(part for item in value if (part := _error_text(item)))
    return str(value) if value is not None else ""


class LogAnalyticsQueryError(RuntimeError):
    """A failed Logs query with the Azure SDK's status and error payload preserved."""

    _MISSING_TABLE_MARKERS = (
        "could not be resolved",
        "failed to resolve table or column expression",
    )

    def __init__(
        self,
        *,
        status: str,
        code: str = "",
        message: str = "",
        details: Any = None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        parts = [f"status={status}"]
        if code:
            parts.append(f"code={code}")
        if message:
            parts.append(f"message={message}")
        detail_text = _error_text(details)
        if detail_text:
            parts.append(f"details={detail_text}")
        super().__init__(f"Log Analytics query failed ({', '.join(parts)})")

    @classmethod
    def from_response(cls, response) -> LogAnalyticsQueryError:
        """Build an error from ``LogsQueryPartialResult.partial_error`` when available."""
        sdk_error = getattr(response, "partial_error", None)
        status = getattr(response.status, "value", str(response.status))
        return cls(
            status=status,
            code=getattr(sdk_error, "code", "") or "",
            message=getattr(sdk_error, "message", "") or "",
            details=getattr(sdk_error, "details", None),
        )

    @property
    def is_missing_table(self) -> bool:
        """Whether Azure's semantic error specifically says a referenced table is absent."""
        semantic_text = " ".join(
            part for part in (self.code, self.message, _error_text(self.details)) if part
        ).lower()
        return any(marker in semantic_text for marker in self._MISSING_TABLE_MARKERS)


def _rows_from_response(response) -> list[dict]:
    """Convert a successful Logs response to rows; retain the full SDK error on failure."""
    if response.status != LogsQueryStatus.SUCCESS:
        raise LogAnalyticsQueryError.from_response(response)
    rows: list[dict] = []
    for table in response.tables:
        for row in table.rows:
            rows.append(dict(zip(table.columns, row)))
    return rows


class LogAnalyticsProvider:
    """Thin KQL query surface over a customer's Cosmos resource logs (resource-centric)."""

    def __init__(self, credential: TokenCredential) -> None:
        self._credential = credential
        self._client = LogsQueryClient(credential)

    @property
    def credential(self) -> TokenCredential:
        """Credential used to build per-worker SDK clients; the token cache is concurrency-safe."""
        return self._credential

    def query_resource(
        self,
        resource_id: str,
        kql: str,
        timespan: tuple[datetime, datetime],
    ) -> list[dict]:
        """Run ``kql`` over the **CDB* logs of one ARM resource** and return rows as dicts.

        Args:
            resource_id: The Cosmos DB **account** ARM resource id (not a workspace GUID). The service
                routes the query to whichever workspace the account exports diagnostic logs to.
            kql: A KQL query string (over a ``CDB*`` table).
            timespan: Absolute ``(start, end)`` window.

        Raises:
            LogAnalyticsQueryError: If the SDK returns a partial result.
            azure.core.exceptions.HttpResponseError: If the service fully rejects the query.
        """
        response = self._client.query_resource(resource_id, kql, timespan=timespan)
        return _rows_from_response(response)

    def cdb_logs_available(self, resource_id: str, timespan: tuple[datetime, datetime]) -> bool:
        """Graceful-degradation probe: do *any* ``CDBDataPlaneRequests`` rows exist for this account?

        Returns ``False`` when the table is absent or no rows exist. Genuine query failures propagate
        so callers cannot misreport a read error as disabled diagnostic settings.
        """
        try:
            rows = self.query_resource(
                resource_id, "CDBDataPlaneRequests | summarize n = count()", timespan
            )
        except LogAnalyticsQueryError as exc:
            if exc.is_missing_table:
                return False
            raise
        return bool(rows) and (rows[0].get("n") or 0) > 0

    def query(
        self,
        workspace_id: str,
        kql: str,
        timespan: tuple[datetime, datetime],
    ) -> list[dict]:
        """Run ``kql`` over a workspace **customer id (GUID)**. Retained for preflight workspace probes.

        Prefer :meth:`query_resource` for detections (no workspace discovery needed).
        """
        response = self._client.query_workspace(workspace_id, kql, timespan=timespan)
        return _rows_from_response(response)


class CachingLogAnalyticsProvider(LogAnalyticsProvider):
    """Per-run memoizing wrapper over a :class:`LogAnalyticsProvider`.

    Within one diagnostic run the analysis window is fixed (the runner anchors a single ``now``), so
    identical Log Analytics calls are pure repeats and can be served once. This collapses the per-run
    fan-out the audit found: DX-002 and DX-007 issue the **same** ``CDBQueryRuntimeStatistics`` fan-out
    KQL on a container, and every LA-backed detection re-probes ``cdb_logs_available`` — without caching
    that is ~8 LA round-trips per container; with it, each distinct ``(resource_id, kql, window)`` runs
    exactly once.

    Subclasses the provider (so it is a drop-in, ``isinstance``-compatible) but wraps an existing
    instance instead of opening its own client. Cache lifetime is the wrapper's lifetime (one run) — it
    keys on the exact window, so different windows never collide and there is no cross-run staleness.
    Exceptions are not cached (a failed query can be retried).
    """

    def __init__(
        self,
        inner: LogAnalyticsProvider,
        *,
        inner_factory: Callable[[], LogAnalyticsProvider] | None = None,
    ) -> None:
        self._inner = inner
        self._credential = getattr(inner, "credential", None)
        self._inner_factory = inner_factory
        self._thread_local = threading.local()
        self._query_cache: dict = {}
        self._avail_cache: dict = {}
        self._query_inflight: dict = {}
        self._avail_inflight: dict = {}
        self._lock = threading.Lock()

    def _inner_for_thread(self) -> LogAnalyticsProvider:
        """Return the LA client for this thread.

        The cache is shared across the run, but Azure SDK clients are not assumed thread-safe. When
        the runner supplies ``inner_factory`` each worker thread gets its own ``LogsQueryClient`` while
        sharing only the Entra credential and the memoized results.
        """
        if self._inner_factory is None:
            return self._inner
        inner = getattr(self._thread_local, "inner", None)
        if inner is None:
            inner = self._inner_factory()
            self._thread_local.inner = inner
        return inner

    def _cached_once(self, cache: dict, inflight: dict, key, compute: Callable[[], _T]) -> _T:
        """Memoize ``compute`` exactly once per key across concurrent workers.

        Distinct KQL keys can still run in parallel, but identical capability/availability probes
        collapse to one network round-trip. Exceptions are not cached, matching the historical retry
        behavior for transient Log Analytics failures.
        """
        while True:
            with self._lock:
                if key in cache:
                    return cache[key]
                event = inflight.get(key)
                if event is None:
                    event = threading.Event()
                    inflight[key] = event
                    break
            event.wait()

        try:
            value = compute()
        except Exception:
            with self._lock:
                inflight.pop(key, None)
                event.set()
            raise
        with self._lock:
            cache[key] = value
            inflight.pop(key, None)
            event.set()
        return value

    def prime_query_resource(
        self, resource_id: str, kql: str, timespan: tuple[datetime, datetime], rows: list[dict]
    ) -> None:
        """Seed an exact query cache entry from a semantically equivalent batched query."""
        key = (resource_id, kql, timespan)
        with self._lock:
            self._query_cache.setdefault(key, rows)

    def prime_cdb_logs_available(
        self, resource_id: str, timespan: tuple[datetime, datetime], available: bool
    ) -> None:
        """Seed the shared CDB availability probe cache for the run's one-day LA window."""
        key = (resource_id, timespan)
        with self._lock:
            self._avail_cache.setdefault(key, available)

    def query_resource(
        self, resource_id: str, kql: str, timespan: tuple[datetime, datetime]
    ) -> list[dict]:
        key = (resource_id, kql, timespan)
        return self._cached_once(
            self._query_cache,
            self._query_inflight,
            key,
            lambda: self._inner_for_thread().query_resource(resource_id, kql, timespan),
        )

    def cdb_logs_available(self, resource_id: str, timespan: tuple[datetime, datetime]) -> bool:
        key = (resource_id, timespan)
        return self._cached_once(
            self._avail_cache,
            self._avail_inflight,
            key,
            lambda: self._inner_for_thread().cdb_logs_available(resource_id, timespan),
        )

    def query(
        self, workspace_id: str, kql: str, timespan: tuple[datetime, datetime]
    ) -> list[dict]:
        return self._inner_for_thread().query(workspace_id, kql, timespan)

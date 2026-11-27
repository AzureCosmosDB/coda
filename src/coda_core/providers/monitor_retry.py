"""Bounded, coordinated retry for read-only Metrics List calls (not Cosmos workload retries)."""

from __future__ import annotations

from datetime import timezone
from email.utils import parsedate_to_datetime
import json
import logging
from math import ceil, isfinite
from random import uniform
from threading import Condition
from time import monotonic, time

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

RETRYABLE = {408, 429, 500, 502, 503, 504}
MAX_ATTEMPTS = 3
WAIT_BUDGET = 60.0
_LOG = logging.getLogger(__name__)


def retry_after(headers, wall_clock=time) -> float | None:
    """Interpret seconds, HTTP dates and Azure milliseconds, without clipping a valid delay."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    for name, scale in (("retry-after", 1), ("retry-after-ms", 1000), ("x-ms-retry-after-ms", 1000)):
        raw = headers.get(name)
        if raw is None:
            continue
        try:
            seconds = float(raw) / scale
        except (TypeError, ValueError, OverflowError):
            if name != "retry-after":
                continue
            try:
                stamp = parsedate_to_datetime(raw)
                seconds = stamp.replace(tzinfo=stamp.tzinfo or timezone.utc).timestamp() - wall_clock()
            except (TypeError, ValueError, OverflowError, OSError):
                continue
        if isfinite(seconds) and seconds >= 0:
            return max(0.0, seconds)
    return None


class MonitorUnavailable(HttpResponseError):
    """Safe detector evidence; no SDK response body, URL, credential or customer name."""

    def __init__(self, reason, status, delay=0):
        self.retry_after_seconds = ceil(delay) if delay > 0 else None
        suffix = f"; retry after {self.retry_after_seconds}s" if self.retry_after_seconds else ""
        super().__init__(f"Azure Monitor {reason}" + (f" (HTTP {status})" if status else "") + suffix)
        self.status_code = status


class RetryBudget:
    """Charge overlapping worker waits only once within a single account report."""

    def __init__(self, deadline=None):
        self.deadline = deadline
        self.spent = 0.0
        self.waiters = 0
        self.since = 0.0
        self.stopped = None

    def remaining(self, now):
        """Return the smaller of remaining wall-clock wait allowance and caller time."""
        spent = self.spent + (now - self.since if self.waiters else 0)
        return min(WAIT_BUDGET - spent, self.deadline - now if self.deadline is not None else WAIT_BUDGET)


class MonitorCooldown:
    """One throttle gate per scan/subscription; only the retrying worker probes recovery."""

    def __init__(self, *, clock=monotonic, jitter=uniform):
        self.clock, self.jitter = clock, jitter
        self.condition = Condition()
        self.until = 0.0
        self.throttled = False
        self.leader = None
        self.generation = 0

    def _admit(self, budget, token, local_until, status):
        with self.condition:
            while True:
                now = self.clock()
                delay = max(0, max(self.until, local_until) - now)
                if budget.stopped:
                    raise MonitorUnavailable(budget.stopped, 429, delay)
                if budget.deadline is not None and now >= budget.deadline:
                    raise MonitorUnavailable("report deadline reached", status, delay)
                waiting_for_probe = self.throttled and self.leader not in (None, token)
                if not delay and not waiting_for_probe:
                    if self.throttled:
                        self.leader = token
                    return self.generation
                remaining = budget.remaining(now)
                if remaining <= 0 or delay > remaining:
                    reason = "retry wait exceeds remaining report budget"
                    if self.throttled:
                        budget.stopped = reason
                    raise MonitorUnavailable(reason, 429 if self.throttled else status, delay)
                if not budget.waiters:
                    budget.since = now
                budget.waiters += 1
                try:
                    self.condition.wait(delay or remaining)
                finally:
                    budget.waiters -= 1
                    if not budget.waiters:
                        budget.spent += self.clock() - budget.since

    def request(self, client, budget, resource, kwargs):
        """Retry idempotent reads only; never convert a transport failure to metric data."""
        token = object()
        local_until, status = 0.0, None
        try:
            for attempt in range(MAX_ATTEMPTS):
                generation = self._admit(budget, token, local_until, status)
                remaining = budget.deadline - self.clock() if budget.deadline is not None else 30
                if remaining <= 0:
                    raise MonitorUnavailable("report deadline reached", status)
                try:
                    # The public SDK drops metric.errorCode on an HTTP 200. In particular a
                    # failed single-metric response may not become zero/empty observations.
                    failures = {}
                    headers = {}
                    hook = kwargs.get("raw_response_hook")

                    def check_response(reply):
                        http = reply.http_response
                        if http.status_code == 200:
                            headers.update(http.headers)
                            for obj in json.loads(http.text()).get("value", ()):
                                code = obj.get("errorCode")
                                if code and code != "Success":
                                    failures[obj["name"]["value"]] = code
                        if hook:
                            hook(reply)

                    result = client.query_resource(resource, **{
                        **kwargs, "retry_total": 0, "connection_timeout": min(5, remaining),
                        "read_timeout": min(30, remaining), "raw_response_hook": check_response,
                    })
                    if failures and (not hook or all(n in failures for n in kwargs["metric_names"])):
                        codes = set(failures.values())
                        code = 429 if codes <= {"TooManyRequests", "Throttled", "Throttling"} else (
                            503 if codes <= {"ServiceUnavailable", "InternalServerError"} else 400)
                        err = MonitorUnavailable("metric query failed: " + ", ".join(sorted(codes)), code)
                        err.monitor_headers = headers
                        raise err
                    if any(code in {"TooManyRequests", "Throttled", "Throttling"} for code in failures.values()):
                        # The batch decoder can retain independently successful sibling metrics.
                        # Honor the throttle for subsequent traffic even on HTTP 200.
                        hint = retry_after(headers)
                        with self.condition:
                            self.generation += 1
                            self.throttled = True
                            self.until = max(self.until, self.clock() + (
                                hint if hint is not None else self.jitter(0.5, 1.0)))
                            self.condition.notify_all()
                except (HttpResponseError, ServiceRequestError, ServiceResponseError) as exc:
                    status = getattr(exc, "status_code", None)
                    if isinstance(exc, HttpResponseError) and status not in RETRYABLE:
                        if isinstance(exc, MonitorUnavailable):
                            raise
                        raise MonitorUnavailable("request rejected", status) from exc
                    hint = retry_after(getattr(exc, "monitor_headers", None) or
                                       getattr(getattr(exc, "response", None), "headers", None))
                    delay = hint if hint is not None else self.jitter(0.5, 1.0) * (2 ** attempt)
                    local_until = self.clock() + delay
                    with self.condition:
                        if status == 429:
                            self.generation += 1
                            self.throttled = True
                            self.until = max(self.until, local_until)
                            if self.leader is None:
                                self.leader = token
                            if attempt == MAX_ATTEMPTS - 1:
                                budget.stopped = "repeatedly throttled; detector reads incomplete"
                            self.condition.notify_all()
                    if attempt == MAX_ATTEMPTS - 1:
                        raise MonitorUnavailable("read failed after three attempts", status, delay) from exc
                    _LOG.info("Azure Monitor read attempt %d failed (%s); retry delay %.2fs",
                              attempt + 1, status or type(exc).__name__, delay)
                else:
                    with self.condition:
                        if self.leader is token and generation == self.generation and self.clock() >= self.until:
                            self.throttled, self.leader = False, None
                            self.condition.notify_all()
                    return result
        finally:
            with self.condition:
                if self.leader is token:
                    self.leader = None
                    self.condition.notify_all()


class MonitorReadClient:
    """Wrap a worker-local SDK client; share only its admission gate and report wait budget."""

    def __init__(self, client, cooldown, budget):
        self.client, self.cooldown, self.budget = client, cooldown, budget

    def query_resource(self, resource_id, **kwargs):
        """Keep the exact SDK query unchanged on retry."""
        return self.cooldown.request(self.client, self.budget, resource_id, kwargs)

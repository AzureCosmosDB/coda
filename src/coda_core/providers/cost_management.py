"""Cost Management provider (read-only).

Reads a customer's **actual Azure cost** from the Cost Management query API so FinOps detections can
express findings in real spend (not just capacity). CODA stays read-only/diagnose-only: this provider
only issues ``query`` POSTs (an aggregation read), never a write.

Auth is Entra ID (the same credential as the other providers). We call the REST endpoint directly via
the credential's token rather than adding an ``azure-mgmt-costmanagement`` dependency — the query API is
a single POST whose request/response shape is pinned here and validated live (see tests + the FinOps
evidence doc). Cost is **subscription- or resource-scoped**; granularity is left to the caller.

Capacity is not cost (ADR-0012): CODA historically expressed savings in RU/s because it lacked billed
rates. With Cost Management read access it *can* attribute real spend, which is why FinOps detections
gate on the ``cost_management`` capability — absent the role, they abstain with "grant Cost Management
Reader" instead of guessing dollars.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date

from azure.core.credentials import TokenCredential

_MGMT = "https://management.azure.com"
_SCOPE = "https://management.azure.com/.default"
_API_VERSION = "2023-11-01"

# The Cost Management query API is aggressively rate-limited (429 with a Retry-After hint). It is a
# best-effort *enrichment* (dollar savings layered on capacity findings), so we retry a bounded number
# of times honoring Retry-After, then let the 429 propagate — the runner degrades to capacity-only
# rather than failing the diagnosis (ADR-0028).
_RATE_LIMIT_MAX_RETRIES = 4
_RATE_LIMIT_DEFAULT_BACKOFF_S = 8.0
_RATE_LIMIT_MAX_BACKOFF_S = 60.0

# Cost Management "type" values. AMORTIZED spreads reservation/savings-plan purchases across the
# usage they cover, so the per-unit figure reflects the customer's *effective discounted rate* — the
# right basis for "what would I save" (ADR-0028). ACTUAL is the as-invoiced charge (lumpy when a
# reservation is purchased) and is kept only for the legacy total/by-resource reads.
AMORTIZED_COST = "AmortizedCost"
ACTUAL_COST = "ActualCost"

# Cosmos DB *provisioned-throughput* meters. The meter taxonomy was validated live against real Cost
# Management data (docs/evidence/finops-cost-derivation.md): provisioned throughput bills under
# MeterCategory "Azure Cosmos DB" with a meter named "... RU/s" ("100 RU/s", "100 Multi-master RU/s").
# This deliberately EXCLUDES storage ("Data Stored"), serverless consumption ("1M RUs" — note "RUs",
# not "RU/s"), and data transfer. The MeterCategory guard is essential: other services emit "RU/s"
# meters too (e.g. Microsoft Defender for Cloud's "Standard 100 RU/s"), which a name-only match would
# wrongly fold into the Cosmos throughput rate.
_COSMOS_METER_CATEGORY = "Azure Cosmos DB"


def is_cosmos_throughput_meter(meter_category: str, meter: str) -> bool:
    """True iff a billing meter is Cosmos **provisioned throughput** (the $/RU/s rate basis)."""
    return meter_category == _COSMOS_METER_CATEGORY and meter.strip().endswith("RU/s")


@dataclass(frozen=True)
class CostResult:
    """Total actual cost over a window, in the subscription's billing currency."""

    amount: float
    currency: str


@dataclass(frozen=True)
class ResourceCost:
    """Actual cost attributed to one ARM resource id over a window."""

    resource_id: str
    amount: float
    currency: str


@dataclass(frozen=True)
class ThroughputCost:
    """Cosmos provisioned-throughput cost **and** billed usage over a window (amortized).

    ``usage`` is in the meter's own unit (100-RU/s-hours), so ``cost / usage`` is a
    duration-independent effective unit price — the key property that lets us derive a $/RU/s rate
    from a customer whose throughput was provisioned for only part of the window (ADR-0028). The
    figure is **discount-inclusive** because it comes from AmortizedCost. ``meters`` records which
    meters contributed (audit trail).
    """

    cost: float
    usage: float
    currency: str
    meters: tuple[str, ...]

    @property
    def has_usage(self) -> bool:
        return self.usage > 0


class CostManagementProvider:
    """Read-only actual-cost queries over a subscription or a sub-scope resource."""

    def __init__(self, credential: TokenCredential, subscription_id: str) -> None:
        self._credential = credential
        self._subscription_id = subscription_id

    def _scope(self, scope: str | None) -> str:
        """Default to the subscription scope; accept any ARM scope (e.g. a resource id)."""
        return scope or f"subscriptions/{self._subscription_id}"

    def _post_query(self, scope: str, body: dict) -> dict:
        """POST a Cost Management query and return the parsed JSON ``properties`` payload.

        Retries on 429 (rate limiting) up to a bounded number of times, honoring the ``Retry-After``
        header. Raises the underlying ``HTTPError`` on non-429 failures (e.g. 403) so the
        preflight/capability layer can classify auth failures exactly like the other providers, and on
        a persistent 429 so the caller can degrade to capacity-only.
        """
        url = f"{_MGMT}/{scope}/providers/Microsoft.CostManagement/query?api-version={_API_VERSION}"
        data = json.dumps(body).encode("utf-8")
        backoff = _RATE_LIMIT_DEFAULT_BACKOFF_S
        for attempt in range(_RATE_LIMIT_MAX_RETRIES + 1):
            token = self._credential.get_token(_SCOPE).token
            req = urllib.request.Request(  # noqa: S310 - fixed https management endpoint
                url, data=data, method="POST",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req) as resp:  # noqa: S310
                    return json.loads(resp.read().decode("utf-8")).get("properties", {})
            except urllib.error.HTTPError as exc:
                if exc.code != 429 or attempt == _RATE_LIMIT_MAX_RETRIES:
                    raise
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                wait_s = float(retry_after) if retry_after and str(retry_after).isdigit() else backoff
                time.sleep(min(wait_s, _RATE_LIMIT_MAX_BACKOFF_S))
                backoff = min(backoff * 2, _RATE_LIMIT_MAX_BACKOFF_S)
        # Unreachable (loop either returns or raises), but keeps type-checkers happy.
        raise RuntimeError("cost management query exhausted retries")  # pragma: no cover

    @staticmethod
    def _window(start: date, end: date, cost_type: str = ACTUAL_COST) -> dict:
        return {"type": cost_type, "timeframe": "Custom",
                "timePeriod": {"from": start.isoformat(), "to": end.isoformat()}}

    @staticmethod
    def _resource_filter(resource_id: str | None) -> dict:
        """A Cost Management ``filter`` scoping a subscription-level query to one ARM resource id."""
        if not resource_id:
            return {}
        return {"filter": {"dimensions": {"name": "ResourceId", "operator": "In",
                                          "values": [resource_id]}}}

    def cosmos_throughput_cost(
        self, start: date, end: date, *, resource_id: str | None = None, scope: str | None = None,
        cost_type: str = AMORTIZED_COST,
    ) -> ThroughputCost:
        """Amortized Cosmos **provisioned-throughput** cost + billed usage over ``[start, end]``.

        Groups spend by ``MeterCategory`` × ``Meter`` and keeps only Cosmos provisioned-throughput
        meters (:func:`is_cosmos_throughput_meter`) — excluding storage, serverless consumption, and
        data transfer. Returns the summed cost and usage (100-RU/s-hours), which the rate model turns
        into a duration-independent, discount-inclusive $/RU/s (ADR-0028).

        ``resource_id`` scopes a subscription-level query to one Cosmos account (the usual call). The
        meter classification still runs because a ResourceId filter alone can leak non-Cosmos meters
        (e.g. Defender's "Standard 100 RU/s") attributed to the resource.
        """
        body = {**self._window(start, end, cost_type),
                "dataset": {"granularity": "None",
                            "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"},
                                            "usage": {"name": "UsageQuantity", "function": "Sum"}},
                            "grouping": [{"type": "Dimension", "name": "MeterCategory"},
                                         {"type": "Dimension", "name": "Meter"}],
                            **self._resource_filter(resource_id)}}
        props = self._post_query(self._scope(scope), body)
        cols = props.get("columns", [])
        rows = props.get("rows") or []
        if not rows:
            return ThroughputCost(0.0, 0.0, "USD", ())
        cost_i = self._col_index(cols, "Cost")
        use_i = self._col_index(cols, "UsageQuantity")
        cat_i = self._col_index(cols, "MeterCategory")
        meter_i = self._col_index(cols, "Meter")
        cur_i = self._col_index(cols, "Currency")
        total_cost = total_usage = 0.0
        currency = "USD"
        meters: list[str] = []
        for r in rows:
            if not is_cosmos_throughput_meter(str(r[cat_i]), str(r[meter_i])):
                continue
            total_cost += float(r[cost_i])
            total_usage += float(r[use_i])
            currency = str(r[cur_i])
            meters.append(str(r[meter_i]))
        return ThroughputCost(total_cost, total_usage, currency, tuple(sorted(set(meters))))

    @staticmethod
    def _col_index(columns: list[dict], name: str) -> int:
        for i, c in enumerate(columns):
            if c.get("name") == name:
                return i
        raise KeyError(name)

    def actual_cost(self, start: date, end: date, *, scope: str | None = None) -> CostResult:
        """Total actual cost over ``[start, end]`` for the subscription (or ``scope`` resource)."""
        body = {**self._window(start, end),
                "dataset": {"granularity": "None",
                            "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}}}}
        props = self._post_query(self._scope(scope), body)
        rows = props.get("rows") or []
        if not rows:
            return CostResult(0.0, "USD")
        cols = props.get("columns", [])
        cost_i = self._col_index(cols, "Cost")
        cur_i = self._col_index(cols, "Currency")
        return CostResult(float(rows[0][cost_i]), str(rows[0][cur_i]))

    def cost_by_resource(self, start: date, end: date, *, scope: str | None = None) -> list[ResourceCost]:
        """Actual cost grouped by ARM ``ResourceId`` (descending) — the per-resource attribution a
        future per-account FinOps detection needs."""
        body = {**self._window(start, end),
                "dataset": {"granularity": "None",
                            "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
                            "grouping": [{"type": "Dimension", "name": "ResourceId"}]}}
        props = self._post_query(self._scope(scope), body)
        cols = props.get("columns", [])
        rows = props.get("rows") or []
        cost_i = self._col_index(cols, "Cost")
        cur_i = self._col_index(cols, "Currency")
        rid_i = self._col_index(cols, "ResourceId")
        out = [ResourceCost(str(r[rid_i]), float(r[cost_i]), str(r[cur_i])) for r in rows]
        out.sort(key=lambda rc: rc.amount, reverse=True)
        return out


__all__ = [
    "CostManagementProvider", "CostResult", "ResourceCost", "ThroughputCost",
    "is_cosmos_throughput_meter", "AMORTIZED_COST", "ACTUAL_COST",
]

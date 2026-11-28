"""Bounded inventory projections for compatible Azure Monitor reads in a single database."""

from __future__ import annotations

from copy import copy
from collections import OrderedDict
from datetime import datetime
from math import ceil, isfinite
import re
from urllib.parse import quote as encode

from azure.core.exceptions import AzureError

from .partition_metrics import SERIES_LIMIT, metadata, quote

COHORT_SIZE = 16
POINT_BUDGET = 50_000
FILTER_BUDGET = 3500
_TERM = re.compile(r"(\w+) eq '((?:[^']|'')*)'")
_SCALAR = {"NormalizedRUConsumption", "TotalRequestUnits", "TotalRequests", "PhysicalPartitionCount", "DataUsage",
           "ProvisionedThroughput"}
_UNITS = {"NormalizedRUConsumption": "Percent", "TotalRequestUnits": "Count", "TotalRequests": "Count",
          "PhysicalPartitionCount": "Count", "DataUsage": "Bytes", "PhysicalPartitionSizeInfo": "Bytes",
          "AutoscaledRU": "Count", "ProvisionedThroughput": "Count"}


class CohortClient:
    """Worker-local view of sibling offers with identical age/mode eligibility, or verified pool members."""

    def __init__(self, client, database, containers, owners):
        self.client, self.db = client, database
        self.axes = {}
        for axis, names in (("CollectionName", containers), ("OfferOwnerRid", owners)):
            names = tuple(names)
            if len(set(names)) == len(names) and all(n and n != "*" for n in names):
                self.axes[axis] = names
        self.groups = OrderedDict()
        self.consumption_observed = set()

    def query_resource(self, rid, **kwargs):
        """Use the original exact read for unmatched scopes, unverified cells and targeted recovery."""
        plan = self._plan(kwargs)
        if plan:
            axis, dims, group, selector, combined, per, needs_count = plan
            key = (rid, tuple(kwargs["metric_names"]), tuple(kwargs["timespan"]), kwargs["granularity"],
                   tuple(kwargs["aggregations"]), combined, kwargs.get("max_results"))
            if key not in self.groups:
                try:
                    cells = self._group_read(rid, kwargs, axis, dims, group, selector, combined, per, needs_count)
                except AzureError as exc:
                    # A transport failure is not a missing cell; do not amplify it into N exact requests.
                    self._store(key, exc)
                else:
                    self._store(key, cells)
            cells = self.groups[key]
            if isinstance(cells, AzureError):
                raise cells
            if dims[axis] in cells:
                return cells[dims[axis]]
        answer = self.client.query_resource(rid, **kwargs)
        if kwargs["metric_names"] == ["TotalRequestUnits"] and any(
                p.total is not None for m in answer.metrics for ts in m.timeseries for p in ts.data):
            self.consumption_observed.update(v.replace("''", "'") for k, v in _TERM.findall(kwargs.get("filter") or "")
                                             if k == "CollectionName")
        return answer

    def _store(self, key, value):
        """Bound retained groups even for a shared pool with thousands of logical members."""
        if len(self.groups) >= 32 and key not in self.groups:
            self.groups.popitem(last=False)
        self.groups[key] = value

    def _plan(self, kwargs):
        """Widen exactly one named dimension for tested shapes, never a targeted recovery or wildcard scope."""
        names = tuple(kwargs["metric_names"])
        filt = kwargs.get("filter") or ""
        terms = [(m[1], m[2].replace("''", "'")) for m in _TERM.finditer(filt)]
        dims = dict(terms)
        span, grain = tuple(kwargs["timespan"]), kwargs["granularity"]
        top = kwargs.get("max_results")
        name = names[0]
        axis = "OfferOwnerRid" if "OfferOwnerRid" in dims else "CollectionName"
        target = dims.get(axis)
        inventory = self.axes.get(axis, ())
        physical_split = dims.get("PhysicalPartitionId") == "*"
        bounded_split = physical_split and (name == "AutoscaledRU" or
                                            ("Region" not in dims and name == "PhysicalPartitionSizeInfo"))
        # Autoscale readers now verify the count at 5m grain on the exact and grouped paths alike.
        needs_count = bounded_split and name == "PhysicalPartitionSizeInfo"
        allowed = (name in _SCALAR and not physical_split) or (
            physical_split and "Region" in dims and name in {"NormalizedRUConsumption", "PhysicalPartitionSizeInfo"}
        ) or bounded_split
        if (len(names) != 1 or not allowed or len(inventory) < 2 or kwargs.get("raw_response_hook")
                or dims.get("DatabaseName") != self.db or len(terms) != len(dims)
                or filt != " and ".join(f"{k} eq {quote(v)}" for k, v in terms)
                or set(dims) - {"DatabaseName", axis, "StatusCode", "Region", "PhysicalPartitionId"}
                or ("PhysicalPartitionId" in dims and not physical_split)
                or any(v == "*" and k != "PhysicalPartitionId" for k, v in terms)):
            return None
        if name == "NormalizedRUConsumption" and not physical_split and grain.total_seconds() == 300:
            inventory = tuple(n for n in inventory if n in self.consumption_observed)
        per = 8 if bounded_split else top if physical_split else 1
        grains = ceil((span[1] - span[0]) / grain)
        if target not in inventory or not per or per >= SERIES_LIMIT or grains <= 0:
            return None
        size = min(COHORT_SIZE, POINT_BUDGET // (grains * per), (SERIES_LIMIT - 1) // per)
        if size <= 1:
            return None
        pos = inventory.index(target) // size * size
        group = inventory[pos:pos + size]
        if needs_count and len(group) < 3:
            return None  # One data call plus one count certificate cannot beat two exact reads.
        selector = "(" + " or ".join(f"{axis} eq {quote(n)}" for n in group) + ")"
        combined = " and ".join(selector if k == axis else f"{k} eq {quote(v)}" for k, v in terms)
        if len(group) > 1 and len(encode(combined, safe="")) <= FILTER_BUDGET:
            return axis, dims, group, selector, combined, per, needs_count
        return None

    def _group_read(self, rid, kwargs, axis, dims, group, selector, combined, per, needs_count):
        """Require separate count evidence for consumers which do not check partition inventory themselves."""
        span, grain = tuple(kwargs["timespan"]), kwargs["granularity"]
        response = self.client.query_resource(rid, **{**kwargs, "filter": combined, "max_results": len(group)*per+1})
        cells = self._checked_cells(response, group, axis, dims, span, grain, kwargs["metric_names"][0],
                                    kwargs["aggregations"][0], per)
        if not needs_count or not cells:
            return cells
        prefix = f"DatabaseName eq {quote(self.db)} and {selector}"
        count_key = (rid, span, grain, prefix, "certificate")
        if count_key not in self.groups:
            count = self.client.query_resource(rid, **{**kwargs, "metric_names": ["PhysicalPartitionCount"],
                                                       "filter": prefix, "max_results": len(group) + 1})
            self._store(count_key, self._checked_cells(count, group, axis, {"DatabaseName": self.db, axis: dims[axis]},
                                                       span, grain, "PhysicalPartitionCount", "Maximum", 1))
        cert = self.groups[count_key]
        return {unit: cell for unit, cell in cells.items() if unit in cert and all(
            p.maximum == len(cell.metrics[0].timeseries) for p in cert[unit].metrics[0].timeseries[0].data)}

    def _checked_cells(self, *args):
        """A malformed batch is not authoritative; use its exact reference path on demand."""
        try:
            return self._project(*args)
        except (TypeError, ValueError, KeyError, AttributeError):
            return {}

    def _project(self, response, group, axis, dims, span, grain, name, agg, per):
        """Only return cells whose identity and timestamp coverage can be established."""
        try:
            echoed = tuple(datetime.fromisoformat(value) for value in response.timespan.split("/"))
        except (ValueError, AttributeError):
            return {}
        if (response.granularity != grain or echoed not in (span, tuple(t.replace(microsecond=0) for t in span))
                or len(response.metrics) != 1 or response.metrics[0].name != name):
            return {}
        metric = response.metrics[0]
        if metric.unit != _UNITS[name] or len(metric.timeseries) >= len(group) * per + 1:
            return {}
        by_member = {n: [] for n in group}
        expected = {k.lower(): v for k, v in dims.items()}
        for ts in metric.timeseries:
            fields = metadata(ts)
            member = fields.get(axis.lower())
            if (member not in by_member or set(fields) != set(expected) or any(
                    (fields[k].casefold() != val.casefold() if k == "region" else fields[k] != val)
                    for k, val in expected.items() if k != axis.lower() and val != "*")):
                return {}
            by_member[member].append(ts)
        projected = {}
        for member, rows in by_member.items():
            if not rows or (per == 1 and len(rows) != 1):
                continue
            if len({tuple(sorted(metadata(row).items())) for row in rows}) != len(rows):
                continue
            if any(not self._grid(row.data, span, grain, agg) for row in rows):
                continue
            cell, selected = copy(response), copy(metric)
            selected.timeseries = rows
            cell.metrics = [selected]
            projected[member] = cell
            if name == "TotalRequestUnits" and any(p.total is not None for row in rows for p in row.data):
                self.consumption_observed.add(member)
        return projected

    @staticmethod
    def _grid(data, span, grain, agg):
        """Azure may label the initial bucket before the exact requested start."""
        if not data or not span[0] - grain < data[0].timestamp <= span[0]:
            return False
        stamps = [p.timestamp for p in data]
        return (len(stamps) == ceil((span[1]-span[0])/grain) and stamps[-1] < span[1]
                and (stamps[-1] + grain >= span[1] or stamps[0] == span[0].replace(second=0, microsecond=0))
                and all(b-a == grain for a, b in zip(stamps, stamps[1:]))
                and all((v := getattr(p, agg.lower())) is None or isfinite(v) for p in data))

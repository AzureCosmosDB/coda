# Log Analytics setup and readiness

[Getting started](../../README.md) | [Detector reference](../detectors.md) | [Permissions](../permissions.md)

Four CODA detectors require Cosmos DB resource logs. Other detectors use configuration and Azure
Monitor metrics, with optional log enrichment for DX-016. **Log Analytics is not required to start
using CODA**, and enabling it does not guarantee that a detector will find a problem.

This page covers shared telemetry setup, not a separate set of detectors. For each detector's
inputs, thresholds, limitations and recommendations, open its detailed methodology from the
[detector catalog](../detectors.md#data-and-interpretation).

## Configure the Cosmos account

These are administrator actions in Azure Portal, not operations performed by CODA:

1. Create or choose a Log Analytics workspace according to your organization's region, retention,
   access-control, and data-handling requirements.
2. Open the **Cosmos DB account > Monitoring > Diagnostic settings > Add diagnostic setting**.
3. Select **DataPlaneRequests5M** for DX-003, DX-010, and optional DX-016 enrichment.
   Add **DataPlaneRequests** and **QueryRuntimeStatistics** if you also need DX-002/DX-007
   query analysis; those checks still require per-request correlation.
4. Select **Send to Log Analytics workspace**, then choose the workspace.
5. Set the destination table mode to **Resource specific** and save.
6. Keep the account serving representative application traffic, then verify ingestion using the
   queries below. Repeat for every account you intend to diagnose.

Official instructions:
[Create diagnostic settings for Azure Cosmos DB](https://learn.microsoft.com/en-us/azure/cosmos-db/monitor-resource-logs?tabs=azure-portal#create-diagnostic-settings).
The Azure CLI equivalent uses `--export-to-resource-specific true`; an ARM diagnostic setting uses
`logAnalyticsDestinationType: "Dedicated"`. Query analysis needs both raw request logs and query
statistics; aggregate-compatible checks do not require those additional categories.

The result is **`CDBDataPlaneRequests5M`**, plus **`CDBDataPlaneRequests`** and
**`CDBQueryRuntimeStatistics`** when query analysis is enabled, not only the legacy
`AzureDiagnostics` table. Existing legacy rows are not converted or backfilled into new tables.
Metrics export is unnecessary: CODA reads Azure Monitor Metrics directly.

Existing raw-only collection remains compatible. CODA prefers five-minute logs when available,
uses raw logs when the five-minute capability is absent/quiet, and never adds both sources together.
Probe/query failures remain visible rather than silently switching sources. An empty selected-source
analysis window remains insufficient data, not an instruction to enable another category.
See [Microsoft's aggregated-log guidance](https://learn.microsoft.com/azure/cosmos-db/monitor-aggregated-logs).

Use the **Analytics** table plan for resource-context queries. Review the workspace's access-control
mode and your effective [resource/workspace/table permissions](../permissions.md). Full-text query
logging is **not required**; avoid enabling it just for CODA because it can expose query literals
and other sensitive information.

## Check log readiness in CODA

After signing in, choose a subscription and resource group. Select an account and choose
**Run Pre-Checks**, or leave Account empty to check the NoSQL accounts in that group.
Alongside logging, the check tests ARM, ARG, metrics and optional subscription Cost Management.
It uses the same SDK credential and source requirements as diagnosis, but does not run detectors
or read application documents.

It reads the account's supported diagnostic categories/settings and probes each required table
in that account's resource context. **A table existing in a shared workspace is not proof that
the selected account exports to it.** Configuration and data are reported separately:

| Result | Meaning / next action |
|---|---|
| Configured, recent data readable | The export is resource-specific and records were observed in the last 24 hours. This is not proof of a complete window, sufficient traffic, or account health. |
| Configured, no recent records | Existing records may be older, or ingestion/workload activity may be pending. Do not blindly enable logging again. |
| Category not configured / no workspace destination | Review the categories required by the affected detectors and configure the Log Analytics destination. |
| Legacy table mode | Verify **Resource specific** mode rather than `AzureDiagnostics`; historical legacy records may still exist after changing settings. |
| Could not verify / access denied | Follow the reported access/service guidance. A failed read is not proof that logging is disabled. |

The observation probe looks back 30 days and reports the latest record timestamp; "recent" means
within the last 24 hours. Log-row counts are not request counts for aggregate tables. A readable
historical table does not prove the export is still enabled. Multiple destinations can have
different history and duplicate exports.

Configured, readable sources show a green check instead of a setup link; the data observation
still identifies older records. Observation times are displayed in the browser's local time zone
to the minute. Structured responses retain precise UTC timestamps for inspection and automation.

The check reports required log paths separately from DX-016's optional enrichment. Metrics,
cost-query access and source readability are probed, while resource age, per-container sample
sufficiency and detector applicability are still assessed during diagnosis. **Analyze account**
and **Scan resource group** remain available after a warning. CODA does not enable collection or
assign roles.

Choose **View fix** on an issue to see its scope and a copy-only PowerShell script or administrator
request. Scripts preview changes unless manually run with `-Apply`. They preserve existing exports,
require an explicit approved workspace, and stop when safe setup cannot be established. Missing
records alone do not justify a role assignment; access mode, table permissions and billing policy
must be distinguished from configuration and ingestion.

## How long should logging run?

**Plan for at least 24 hours of representative collected logs, plus ingestion delay**, before
interpreting the four log-dependent detectors as a full-window observation.

| Detector | Required tables | Production analysis window |
|---|---|---|
| DX-002 Cross-partition query fan-out | `CDBQueryRuntimeStatistics` **and** `CDBDataPlaneRequests` | 1 day |
| DX-003 Shared-throughput starvation | `CDBDataPlaneRequests5M`, or raw `CDBDataPlaneRequests` | 1 day |
| DX-007 Shard-key misalignment | `CDBQueryRuntimeStatistics` **and** `CDBDataPlaneRequests` | 1 day |
| DX-010 Uncontrolled ingestion | `CDBDataPlaneRequests5M`, or raw `CDBDataPlaneRequests` | 1 day |
| DX-016 Optional consistency-cost enrichment | `CDBDataPlaneRequests5M`, or raw `CDBDataPlaneRequests` | 1 day; the configuration finding does not require it |

The two query detectors join request charges from `CDBDataPlaneRequests` because query statistics
alone do not provide request charge. RU is reported as evidence only, not used as a finding
gate. Share, fan-out query rate and physical partition count drive the structural decisions.

Five-minute production analysis retains a full 24 hours ending at the latest completed UTC
five-minute boundary. Its end can therefore precede the report time by less than five minutes.
Explicit analysis/eval windows must have five-minute-aligned boundaries when that source is
selected; partial buckets are rejected, not interpolated. Ingestion can still be delayed.
Reports retain the selected source and absolute observation window.
Relative eval-hour requests construct aligned intervals automatically; explicitly pinned end
timestamps are preserved and must already satisfy the selected source's boundary requirements.

DX-010's supporting burst factor uses five-minute write buckets for aggregates and one-minute
buckets for raw logs. It averages observed write buckets, not an invented zero-filled history.
The reported resolution is explicit; the two factors are not interchangeable. Trigger/severity
thresholds are unchanged.

Three separate constraints matter:

- **Collection history:** settings collect future events only. They cannot recover yesterday's logs
  if enabled today. Retain at least the intended analysis window; longer retention supports later
  investigation but has cost and privacy implications.
- **Ingestion delay:** records appear after the operation, not instantly. Delay varies; there is no
  fixed 5- or 15-minute guarantee. Verify actual timestamps rather than waiting an assumed interval.
- **Representative volume:** a quiet account may not meet minimum request/query counts even after
  24 hours. Query detectors need actual query traffic; shared-pool detection needs an applicable
  shared-throughput database and traffic from multiple containers.

CODA may evaluate a partially populated window when its sample thresholds are met. **Do not assume
it proves that every minute of the requested window exists**, or that it always abstains until a
complete day has accumulated. Inspect the evidence and your collection start time.

The capability probe looks back up to **30 days** to distinguish a table that has been quiet recently
from a table with no accessible evidence. That probe is **not a requirement to collect 30 days of
logs**. Some separate metrics detectors do analyze 7 or 30 days; see [detector windows](../detectors.md).

## Verify data without changing resources

In the selected workspace's **Logs** blade, replace the placeholder with the target account's full
resource ID and run each query separately. Set the Portal time picker to cover the queried period.

```kusto
CDBDataPlaneRequests5M
| where _ResourceId =~ "<cosmos-account-resource-id>"
| where TimeGenerated >= ago(24h)
| summarize AggregateRows=count(), Requests=sum(RequestCount), RequestCharge=sum(TotalRequestCharge),
    First=min(TimeGenerated), Last=max(TimeGenerated)
```

For query analysis, also check both of its required tables:

```kusto
CDBDataPlaneRequests
| where _ResourceId =~ "<cosmos-account-resource-id>"
| where TimeGenerated >= ago(24h)
| summarize Rows=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
```

```kusto
CDBQueryRuntimeStatistics
| where _ResourceId =~ "<cosmos-account-resource-id>"
| where TimeGenerated >= ago(24h)
| summarize Rows=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
```

These are interactive setup checks; CODA itself uses absolute analysis windows. Nonzero counts and
first/last timestamps demonstrate available records, **not continuous or complete coverage**.
Use `RequestCount` for represented requests in five-minute logs; `count()` counts aggregate rows,
not requests. Use total charge, or total charge divided by total requests for a weighted average.
Run the checks as the same principal used for CODA when investigating access problems. Workspace
query success alone does not prove that resource-context access is configured correctly.

When an account exports to multiple workspaces, compare each destination independently during
validation. Resource-context queries can include multiple destinations; differing collection start
times and duplicate exports are not evidence that all sources contain the same history.

## Interpreting an incomplete check

| Result or symptom | What to check |
|---|---|
| Enable diagnostics / missing table | Categories required by that detector, correct workspace, Resource specific mode, Analytics plan, account attribution, and readable rows |
| Configured but quiet / insufficient data | Recent representative traffic, ingestion timestamps, minimum samples, retention, and detector applicability |
| Unauthorized / forbidden | Effective identity, workspace access-control mode, and table/resource permissions |
| Only `AzureDiagnostics` has rows | Configure resource-specific collection; allow new rows to arrive |
| Tables have data but no finding | The observed behavior may not cross the detector's thresholds; successful execution is not a positive finding |
| Metric-based check needs more history | Log configuration will not create missing metric samples or make a new resource old enough |

## Cost and privacy

Resource-log ingestion and retention can incur Log Analytics charges, especially for busy accounts.
Estimate volume and apply your organization's budget, retention, and access policies before enabling
collection across many accounts.

A bounded collection period can support a one-time investigation. If an administrator later disables
the setting, new logs stop; existing retained rows remain subject to retention, and future diagnoses
progressively lose recent evidence. Keep logging enabled when recurring diagnostics or incident
investigation require ongoing coverage. CODA never enables or disables it for you.

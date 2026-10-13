# Log Analytics setup and readiness

[Getting started](../../README.md) | [Detector reference](../detectors.md) | [Permissions](../permissions.md)

Four CODA detectors require Cosmos DB resource logs. Other detectors use configuration and Azure
Monitor metrics, with optional log enrichment for DX-016. **Log Analytics is not required to start
using CODA**, and enabling it does not guarantee that a detector will find a problem.

## Configure the Cosmos account

These are administrator actions in Azure Portal, not operations performed by CODA:

1. Create or choose a Log Analytics workspace according to your organization's region, retention,
   access-control, and data-handling requirements.
2. Open the **Cosmos DB account > Monitoring > Diagnostic settings > Add diagnostic setting**.
3. Select both **DataPlaneRequests** and **QueryRuntimeStatistics** log categories.
4. Select **Send to Log Analytics workspace**, then choose the workspace.
5. Set the destination table mode to **Resource specific** and save.
6. Keep the account serving representative application traffic, then verify ingestion using the
   queries below. Repeat for every account you intend to diagnose.

Official instructions:
[Create diagnostic settings for Azure Cosmos DB](https://learn.microsoft.com/en-us/azure/cosmos-db/monitor-resource-logs?tabs=azure-portal#create-diagnostic-settings).
The Azure CLI equivalent uses `--export-to-resource-specific true`; an ARM diagnostic setting uses
`logAnalyticsDestinationType: "Dedicated"`. CODA needs both categories, not only query statistics.

The result must be **`CDBDataPlaneRequests`** and **`CDBQueryRuntimeStatistics`** tables, not only the
legacy `AzureDiagnostics` table. Existing legacy rows are not converted or backfilled into the new
tables. Metrics export is unnecessary: CODA reads Azure Monitor Metrics directly.

Use the **Analytics** table plan for resource-context queries. Review the workspace's access-control
mode and your effective [resource/workspace/table permissions](../permissions.md). Full-text query
logging is **not required**; avoid enabling it just for CODA because it can expose query literals
and other sensitive information.

## How long should logging run?

**Plan for at least 24 hours of representative collected logs, plus ingestion delay**, before
interpreting the four log-dependent detectors as a full-window observation.

| Detector | Required tables | Production analysis window |
|---|---|---|
| DX-002 Cross-partition query fan-out | `CDBQueryRuntimeStatistics` **and** `CDBDataPlaneRequests` | 1 day |
| DX-003 Shared-throughput starvation | `CDBDataPlaneRequests` | 1 day |
| DX-007 Shard-key misalignment | `CDBQueryRuntimeStatistics` **and** `CDBDataPlaneRequests` | 1 day |
| DX-010 Uncontrolled ingestion | `CDBDataPlaneRequests` | 1 day |
| DX-016 Optional consistency-cost enrichment | `CDBDataPlaneRequests` | 1 day; the configuration finding does not require it |

The two query detectors join request charges from `CDBDataPlaneRequests` because query statistics
alone do not provide the RU cost needed by their cost gate.

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
Run the checks as the same principal used for CODA when investigating access problems. Workspace
query success alone does not prove that resource-context access is configured correctly.

## Interpreting an incomplete check

| Result or symptom | What to check |
|---|---|
| Enable diagnostics / missing table | Both categories enabled, correct workspace, Resource specific mode, Analytics plan, account attribution, and readable rows |
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

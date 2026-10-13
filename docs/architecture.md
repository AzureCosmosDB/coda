# Architecture and data flow

[Getting started](../README.md) | [Detectors](detectors.md) | [Permissions](permissions.md)

CODA is a **local, single-user, read-only** Python application for Azure Cosmos DB for NoSQL.
There is no hosted CODA service to deploy. The browser UI and MCP adapter use one diagnostic
engine; neither implements a second set of detection rules.

## Components

| Public path | Responsibility |
|---|---|
| `src/coda_core/cli.py` | Installed `coda web` and `coda mcp` entry points |
| `src/coda_web/public_app.py` | FastAPI local web API, subscription/account discovery, selected-resource-group scan enforcement |
| `src/coda_web/local_auth.py` | Explicit local sign-in state and lazy `DefaultAzureCredential` construction |
| `src/coda_web/public_static/` | Browser UI and Azure Portal link builder, served by the same local process |
| `src/coda_core/mcp_server.py` | Optional MCP stdio adapter |
| `src/coda_core/mcp_tools.py` | Shared operations returning JSON-compatible reports |
| `src/coda_core/scan.py` | Account discovery and bounded concurrent shallow/deep scans |
| `src/coda_core/pipeline/` | Resource selection, capability checks, detector execution, correlation, and report assembly |
| `src/coda_core/detections/` | Deterministic detection rules |
| `src/coda_core/providers/` | Read-only ARM, Metrics, Log Analytics, cost, and public-price clients |
| `src/coda_core/framework/` | Shared environment classification, utilization, and cost calculations |
| `docs/` | User-facing setup and reference documentation |

The public repository contains the product, curated documentation, package metadata, and offline
package tests. It is a generated distribution, not a second independently maintained codebase;
see [contribution policy](../CONTRIBUTING.md).

## What happens during a diagnosis

1. **Choose scope and credentials.** The browser talks to the loopback FastAPI service. MCP uses
   stdio. Azure credentials are resolved locally through the Azure Identity library.
2. **Discover resources.** ARM supplies account configuration and throughput offers. The web app
   can accelerate account discovery with Azure CLI Resource Graph; it falls back to ARM if that
   path is unavailable. Discovery reads subscription inventory, not every account's diagnostics.
3. **Determine applicability and availability.** The engine distinguishes account, shared-database,
   dedicated-container, and serverless checks. It checks which resource-log tables are accessible.
4. **Read evidence.** Detectors request metrics and logs over absolute start/end windows. The run
   caches repeated queries; concurrent workers use separate SDK clients. Cost/pricing enrichment
   is optional and carries its own provenance.
5. **Evaluate and correlate.** Rules produce findings, not-detected results, abstentions, or errors.
   Correlation groups related signals and avoids counting superseded findings as independent impact.
6. **Render a report.** The browser shows recommendations and incomplete evaluations. JSON/MCP
   retains evidence, identifiers, thresholds, and remediation-rule metadata.

The shipped diagnostic path does not call an LLM. An AI client can call the MCP tools and interpret
their output, but that client's model service is separate from CODA.

## Services and outbound connections

These are the public Azure endpoints used by the current implementation, not a complete firewall
allowlist for every identity flow. Your proxy, tenant policy, SDK configuration, and Azure network
configuration can add requirements.

| Service | Why CODA calls it | Typical endpoint / access |
|---|---|---|
| Microsoft Entra ID | Acquire delegated/local Azure tokens | `login.microsoftonline.com`; your local Azure credential chain |
| Azure Resource Manager | Account, database, container, throughput, subscription metadata and Activity Log reads | `management.azure.com`; Reader-tier resource access |
| Azure Monitor Metrics | RU utilization, request status/operation counts, storage and partition metrics | Azure Monitor management APIs; no diagnostic-log export needed |
| Azure Resource Graph | Optional fast web account inventory through `az graph query` | Azure Resource Manager; existing CLI login and resource-graph extension |
| Azure Monitor Logs / Log Analytics | Resource-context KQL over the selected account's `CDB*` tables | Azure Monitor Logs API (`api.loganalytics.io` SDK default); resource/workspace log access |
| Azure Cost Management Query API | Optional customer amortized throughput rate | `management.azure.com`; queries are read-only POSTs, normally subscription-scoped |
| Azure Retail Prices API | Optional public list-price estimate for eligible paid continuous-backup storage | `prices.azure.com/api/retail/prices`; no Azure credentials or customer identifiers sent |

No Cosmos DB document SDK or application-document access is required. CODA does not use account
keys, write resources, execute remediations, enable diagnostics, or provision infrastructure.
The current clients use public Azure defaults; sovereign-cloud compatibility is not claimed here.

Package installation connects to GitHub Release assets and the public Python package index/CDN.
Clicking help, Portal, or feedback links opens Microsoft Learn, Azure Portal, or GitHub in your
browser; those links are not automatic report uploads.

## Identity and data boundaries

Use `az login` for the simplest local workflow. `DefaultAzureCredential` can select an earlier
credential in its chain, such as an environment-configured identity. Resource Graph discovery
uses the Azure CLI's identity independently, so keep CLI and SDK credentials aligned.
CODA creates no application registration and requires no client secret.

The web process has process-wide sign-in state, not per-user authenticated sessions. Bind it to
`127.0.0.1` and do not use it as a remotely shared service. Azure access is still enforced by the
signed-in principal's RBAC, network policy, and conditional access.

Telemetry is read from your Azure resources into local process memory and returned to your
browser or MCP client. Reports can include resource names/IDs, configuration, billing-derived
amounts, query text/shapes present in diagnostic logs, and SDK user-agent details. **Not reading
documents does not mean reports are non-sensitive.** Full-text query logging can increase the
sensitivity of those logs; it is not required for CODA.

CODA does not automatically submit reports to GitHub. If you export feedback, review the redacted
artifact before submitting it. If you use MCP with an external AI service, that service's data
handling is outside CODA's local boundary.

## Windows, confidence, and incomplete results

Production windows are detector-specific, from recent configuration/snapshots through 30 days of
metrics. Four log-dependent detectors query 24 hours of resource logs. Age gates, minimum sample
counts, applicability, and configuration still apply; a configured source is not proof of complete
history. See the [catalog](detectors.md) and [Log Analytics readiness](detections/log-analytics-readiness.md).

`threshold_status` distinguishes calibrated/configuration-based rules from proposal thresholds;
it is not a certification that every detector has been independently validated against your
workload. `not_detected` applies only to the executed check and observed window. An abstention or
error does not establish that the resource is healthy.

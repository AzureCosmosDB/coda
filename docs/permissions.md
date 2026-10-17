# Permissions and sign-in

[Getting started](../README.md) | [Architecture](architecture.md) | [Log setup](detections/log-analytics-readiness.md)

CODA is **diagnose-only and read-only**. It uses Microsoft Entra ID, not Cosmos DB account keys.
The person running CODA needs permission to read configuration and monitoring data. The administrator
who enables diagnostic settings needs separate write permission; CODA never performs that setup.

## Local sign-in

Install Azure CLI, then authenticate to the tenant containing your resources:

```console
az login --tenant "<tenant-id>"
az account set --subscription "<subscription-id>"
az account show --query "{name:name,id:id,tenantId:tenantId}" --output table
```

Start `coda web` and select **Sign in**. This constructs `DefaultAzureCredential` and checks that a
token can be obtained; it does not create a CODA account. If your organization requires MFA or
conditional access, complete the appropriate Azure CLI login flow.

`DefaultAzureCredential` may select another configured credential before Azure CLI. For example,
environment-based credentials can take precedence over your CLI login. Resource Graph discovery
and pre-checks use that same SDK credential, rather than a separate CLI identity.
Do not add client secrets or account keys to CODA configuration to work around a permission failure.

See [DefaultAzureCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential)
for credential-chain behavior. Restart CODA after changing credential environment variables.

## Read access and scope

Ask an RBAC administrator to assign access to your user or security group at the narrowest scope
that covers the resources you intend to diagnose. Use **Access control (IAM) > Check access** in
Azure Portal to inspect your effective assignments; CODA does not assign roles.

| Purpose | Relevant read operations | Role and scope guidance |
|---|---|---|
| Cosmos account, SQL database/container, and throughput configuration | `Microsoft.DocumentDB/databaseAccounts/read` and the corresponding `sqlDatabases`, `containers`, and `throughputSettings` read operations | **Reader** on the target account or resource group |
| Azure Monitor metrics and definitions | `Microsoft.Insights/metrics/read`, `Microsoft.Insights/metricDefinitions/read` | **Reader** includes `*/read`; **Monitoring Reader** also works at the target resource/RG scope |
| Subscription discovery/metadata and resource-age Activity Log reads | `Microsoft.Resources/subscriptions/read`, `Microsoft.Insights/eventtypes/values/read` | Subscription-level **Reader** or **Monitoring Reader** provides the broadest straightforward local experience; narrower/custom access may limit discovery or age evidence |
| Resource-context queries over `CDB*` logs | Resource log-read access, plus workspace/table access when required by its access mode | See the workspace rules below; a workspace-wide grant is not always required |
| Optional amortized-cost enrichment | `Microsoft.CostManagement/query/read` | **Cost Management Reader** at the subscription scope used by CODA, subject to billing policy |

For an uncomplicated setup, Reader on the selected subscription covers the configuration, metrics,
and subscription reads. **That is broader than resource-group-only diagnostic access**, not a claim
of universal least privilege. If access must remain account/RG-scoped, start there and verify discovery,
resource-age information, and effective capabilities with your administrator. Do not grant a whole
subscription solely because a detector lacks logs.

The web scan's resource-group filter limits what is diagnosed; it does not narrow an Azure role
assignment or prevent subscription metadata discovery.

## Log Analytics workspace permissions

CODA calls **resource-context** log queries for a Cosmos account, rather than querying all rows in a
workspace. Access depends on the workspace's **Access control mode**, table plan, and granular RBAC:

| Workspace access control mode | What the CODA user needs |
|---|---|
| **Use resource or workspace permissions** | Resource-context log-read permission on the account can suffice for its attributed records. A separate workspace-wide Reader role is not invariably needed. |
| **Require workspace permissions** | Workspace/table read grants are required even for resource-context queries. **Log Analytics Data Reader** on the workspace is a suitable data-reading role; **Log Analytics Reader** is broader. |

Log Analytics Data Reader includes workspace/query and workspace read actions and
`Microsoft.OperationalInsights/workspaces/tables/data/read`. Table-level/granular assignments can
further constrain access. Resource-context queries depend on resource attribution (`_ResourceId`)
and the **Analytics** table plan; do not assume Basic or Auxiliary tables work for CODA.

See [Manage access to Log Analytics workspaces](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access)
for current access-mode, table-plan, and granular-RBAC behavior.

### Optional pre-checks and guided fixes

**Run Pre-Checks** tests ARM/ARG reads, metrics, logs and optional subscription Cost Management.
It also reads the account's diagnostic settings and supported categories. Reader-level
ARM access can provide these metadata reads; it does not require permission to write settings.
A group check needs permission to enumerate the group's accounts; a named-account check uses
that account directly. Log queries use the same resource-context permissions described above.
If configuration cannot be read but logs are readable, CODA reports that distinction rather than
calling the account unconfigured. Successful probes do not prove all descendant access, complete
data history or detector sample/age requirements. Empty cost/metric data is not a permission failure.

Issue popups distinguish runtime read permissions from permissions needed to apply a fix:

| Purpose | Narrow runtime access | Authority required to grant/configure it |
|---|---|---|
| ARM, ARG and metrics | Reader at the selected account/RG, subject to the reads being requested | `Microsoft.Authorization/roleAssignments/write` at that scope |
| Cost Management | Cost Management Reader at the subscription queried by CODA, subject to billing policy | Role-assignment write authority at that subscription |
| Workspace-only log access | Log Analytics Data Reader at the verified workspace when its access mode requires it | Role-assignment write authority at that workspace |
| Enable resource-specific logs | No write role is needed by CODA itself | `Microsoft.Insights/diagnosticSettings/write` on the Cosmos account, plus read access to the chosen workspace |

CODA never grants those administrative rights to itself. If required authority or requester identity
cannot be verified, the popup provides an administrator request rather than a runnable fix. It names
the original requester object ID, tenant, narrow scope and required role/action. Ambiguous log access
or a failure despite reported read rights requires policy/scope review, not a blanket workspace grant.

Generated PowerShell uses Azure CLI and is **copy-only**. It previews by default; an operator must
review it and explicitly supply `-Apply` outside CODA. It does not select a new identity, change the
CLI's default subscription, delete/replace existing diagnostic exports, or create a workspace.
Administrative rights are evaluated from reported scope permissions, not role names alone; PIM,
conditions, deny assignments and Azure Policy can still prevent the operation.

## Optional cost information

CODA uses the Cost Management **Query API** to obtain a customer's amortized Cosmos throughput
rate. These HTTP POST requests are read-only aggregations, not resource writes. The current provider
queries subscription scope and filters the relevant account; a role scoped only to a resource group
does not necessarily authorize that subscription-scoped request.

Access can come from an existing read role or a dedicated **Cost Management Reader** assignment.
Billing-account policy can still restrict charge visibility; for example, enterprise billing
administrators may need to enable charge visibility. A role assignment alone does not guarantee
usable cost rows, billing coverage, or an applicable throughput rate.

Without a usable cost rate, eligible findings remain capacity/recommendation-only rather than
inventing currency savings. Container-level estimates allocate account-level billing information;
they are not independently billed container charges. Optional backup-storage estimates use public
retail prices and have different provenance from bill-derived throughput estimates.

The report's incomplete section explains missing dollar estimates separately from detector/resource
abstentions. For example, HTTP 429 is Cost Management rate limiting, not evidence of missing access.
Capacity findings remain valid; wait before retrying rather than repeatedly querying cost data or
assigning roles. Authentication/access failures, timeouts and unavailable billing rates have their
own explanations. Structured reports expose `cost_estimate_issue` when enrichment is unavailable;
this optional account-level issue does not increase the number of incomplete detector evaluations.

CODA does not create cost exports, buy reservations, generate Cost Details reports, or change billing
settings. Those permissions are not prerequisites for this release.

## Administrator setup versus CODA runtime

An administrator must create or select a Log Analytics workspace and add the Cosmos diagnostic
setting using **Resource specific** destination tables. **DataPlaneRequests5M** supports DX-003,
DX-010, and optional DX-016 enrichment. **DataPlaneRequests** plus **QueryRuntimeStatistics**
are additionally required for DX-002/DX-007 query analysis. Existing raw-only request collection
remains supported for aggregate-compatible checks. Follow the
[setup guide](detections/log-analytics-readiness.md).

That setup needs permission to write diagnostic settings and select the destination; creating a new
workspace requires additional provisioning permission. These are **not** permissions to grant to
CODA simply to run diagnostics. Account keys, document data-plane roles, Contributor, and Owner are
not required by CODA's read-only runtime. Avoid Cosmos DB roles that unnecessarily grant key access.

## Troubleshooting

- **Authentication failed:** check tenant, token expiry, conditional access, and credential-chain
  selection. Authentication success does not prove authorization to all data sources.
- **No subscriptions/accounts:** inspect effective scope and the UI's **All subscriptions** filter.
  Web discovery currently lists NoSQL accounts.
- **403 / forbidden:** identify the failing resource/data source before broadening access. A Logs
  failure can be a workspace access-mode or table restriction rather than Cosmos configuration RBAC.
- **No logs or insufficient data:** verify settings, actual table rows, traffic, retention, and
  ingestion; extra roles do not create missing history.
- **No currency savings:** check cost access and rate availability separately from detector findings.

## Role references

- [Reader](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general#reader)
- [Monitoring and Log Analytics roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/monitor)
- [Cosmos DB read operations](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/databases#microsoftdocumentdb)
- [Azure Monitor read operations](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/monitor)
- [Cost Management Reader](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/management-and-governance#cost-management-reader)

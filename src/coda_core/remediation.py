"""Copy-only, narrowly scoped PowerShell and administrator requests; never execute Azure writes."""

from __future__ import annotations

import uuid

from coda_core.providers.management import ManagementReader

ROLES = {
    "reader": ("Reader", "acdd72a7-3385-48ef-bd42-f606fba81ae7"),
    "cost": ("Cost Management Reader", "72fafb9e-0641-4937-9268-a91bfd8191a3"),
    "logs": ("Log Analytics Data Reader", "3b03c2da-16b3-4a49-8834-0f8130efdd3b"),
}
ROLE_WRITE = "Microsoft.Authorization/roleAssignments/write"
DIAGNOSTIC_WRITE = "Microsoft.Insights/diagnosticSettings/write"
_CAVEAT = (
    "CODA does not execute this script. Reported permissions are not a guarantee: PIM, "
    "role conditions, deny assignments and Azure Policy can still block the operation. "
    "Do not grant Owner or an administrator role to CODA just to run diagnostics."
)


def _ps(value: str) -> str:
    """Quote data as a PowerShell literal, never as executable command text."""
    return "'" + value.replace("'", "''") + "'"


_COMMON = r"""
# Requires Azure CLI and an existing sign-in approved by your organization.
$ErrorActionPreference = 'Stop'
Get-Command az -ErrorAction Stop | Out-Null

function Invoke-AzJson {
    param([string[]]$Arguments)
    $output = & az @Arguments --only-show-errors --output json
    if ($LASTEXITCODE -ne 0) {
        throw 'Azure CLI failed. Inspect the error and any possibly completed operation before retrying.'
    }
    if ($output) { return ($output -join "`n" | ConvertFrom-Json) }
}

function Assert-Tenant {
    param([string]$Subscription)
    $context = Invoke-AzJson @('account','show','--subscription',$Subscription)
    if ($context.tenantId -ine $TenantId) {
        throw 'The Azure CLI tenant does not match the requester tenant. Do not grant access across an unverified tenant.'
    }
}

function Assert-ReportedPermission {
    param([string]$TargetScope, [string]$Action, [string]$Subscription)
    $url = "https://management.azure.com$TargetScope/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    $allowed = $false
    for ($page = 0; $page -lt 20 -and $url; $page++) {
        $uri = [Uri]$url
        if ($uri.Scheme -ne 'https' -or $uri.Authority -ne 'management.azure.com') {
            throw 'Unexpected permission paging endpoint.'
        }
        $result = Invoke-AzJson @('rest','--method','get','--url',$url,'--subscription',$Subscription)
        foreach ($permission in $result.value) {
            $granted = @($permission.actions | Where-Object { $Action -like $_ }).Count -gt 0
            $excluded = @($permission.notActions | Where-Object { $Action -like $_ }).Count -gt 0
            if ($granted -and -not $excluded -and -not $permission.condition) { $allowed = $true }
        }
        $url = $result.nextLink
    }
    if ($url -or -not $allowed) {
        throw "Required reported permission not verified: $Action at $TargetScope. Ask an authorized administrator."
    }
}
"""


def _role_script(identity: dict, scope: str, role: str) -> str:
    """Keep the original requester fixed even when a different administrator executes the script."""
    name, role_id = ROLES[role]
    subscription = str(uuid.UUID(scope.split("/")[2]))
    return (
        "# Reference: https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli\n"
        "[CmdletBinding()]\nparam([switch]$Apply)\n"
        f"$TenantId = {_ps(identity['tenant_id'])}\n"
        f"$PrincipalObjectId = {_ps(identity['object_id'])}\n"
        f"$SubscriptionId = {_ps(subscription)}\n$Scope = {_ps(scope)}\n"
        f"$RoleName = {_ps(name)}\n$RoleId = {_ps(role_id)}\n"
        + _COMMON + r"""
Assert-Tenant $SubscriptionId
Write-Output "Requester: $PrincipalObjectId; role: $RoleName; scope: $Scope"
Write-Output 'Review inherited access, PIM and organization policy. This grants a runtime read role, not administration.'
if (-not $Apply) { Write-Output 'Preview only. Save and rerun with -Apply after review.'; return }
Assert-ReportedPermission $Scope 'Microsoft.Authorization/roleAssignments/write' $SubscriptionId
$existing = @(Invoke-AzJson @('role','assignment','list','--scope',$Scope,'--include-inherited',
    '--fill-principal-name','false','--all','--subscription',$SubscriptionId) |
    Where-Object { $_.principalId -ieq $PrincipalObjectId -and $_.roleDefinitionId.Split('/')[-1] -ieq $RoleId })
if ($existing.Count -gt 0) { Write-Output 'A matching direct/inherited assignment already exists. No change made.'; return }
$assignment = Invoke-AzJson @('role','assignment','create','--assignee-object-id',$PrincipalObjectId,
    '--role',$RoleId,'--scope',$Scope,'--subscription',$SubscriptionId)
if ($assignment.principalId -ine $PrincipalObjectId -or
    $assignment.roleDefinitionId.Split('/')[-1] -ine $RoleId -or $assignment.scope -ine $Scope) {
    throw 'Role assignment readback did not match the requested principal, role and scope.'
}
Write-Output "Created assignment $($assignment.id). Allow propagation, then rerun CODA pre-checks."
"""
    )


def _logging_script(identity: dict, account_id: str, category: str) -> str:
    """Add only a missing category in a new setting; never replace or delete existing exports."""
    if category not in {"DataPlaneRequests5M", "DataPlaneRequests", "QueryRuntimeStatistics"}:
        raise ValueError("Unsupported diagnostic category.")
    subscription = str(uuid.UUID(account_id.split("/")[2]))
    return (
        "# Reference: https://learn.microsoft.com/en-us/azure/cosmos-db/monitor-resource-logs\n"
        "[CmdletBinding()]\nparam([Parameter(Mandatory)][string]$WorkspaceResourceId, [switch]$Apply)\n"
        f"$TenantId = {_ps(identity['tenant_id'])}\n$SubscriptionId = {_ps(subscription)}\n"
        f"$AccountId = {_ps(account_id)}\n$Category = {_ps(category)}\n"
        + _COMMON + r"""
if ($WorkspaceResourceId -notmatch '^/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/[\w().-]{1,90}/providers/Microsoft\.OperationalInsights/workspaces/[a-zA-Z0-9][a-zA-Z0-9-]{3,62}$') {
    throw 'Supply an existing Log Analytics workspace ARM resource ID. CODA does not choose or create a workspace.'
}
$WorkspaceSubscription = $Matches[1]
Assert-Tenant $SubscriptionId
Assert-Tenant $WorkspaceSubscription
$workspace = Invoke-AzJson @('rest','--method','get','--url',
    "https://management.azure.com${WorkspaceResourceId}?api-version=2022-10-01",'--subscription',$WorkspaceSubscription)
if ($workspace.id -ine $WorkspaceResourceId) { throw 'Workspace identity could not be verified.' }
$base = "https://management.azure.com$AccountId/providers/Microsoft.Insights"
$categories = Invoke-AzJson @('rest','--method','get','--url',
    "$base/diagnosticSettingsCategories?api-version=2021-05-01-preview",'--subscription',$SubscriptionId)
$supported = @($categories.value | Where-Object { $_.name -ieq $Category })
if ($supported.Count -ne 1) { throw 'The account does not advertise this diagnostic category.' }
$settings = Invoke-AzJson @('rest','--method','get','--url',
    "$base/diagnosticSettings?api-version=2021-05-01-preview",'--subscription',$SubscriptionId)
if ($null -eq $settings -or $null -eq $settings.PSObject.Properties['value'] -or $settings.nextLink) {
    throw 'A complete diagnostic-settings list was not returned. No changes will be attempted.'
}
foreach ($setting in $settings.value) {
    if (-not $setting.properties.workspaceId -or $setting.properties.logAnalyticsDestinationType -ine 'Dedicated') { continue }
    foreach ($log in $setting.properties.logs) {
        if ($log.enabled -and ($log.category -ieq $Category -or $log.categoryGroup -ieq 'allLogs' -or
            ($log.categoryGroup -and $supported[0].properties.categoryGroups -icontains $log.categoryGroup))) {
            Write-Output "This category is already exported in resource-specific mode by $($setting.name). No change made."
            return
        }
    }
}
if (@($settings.value).Count -ge 5) {
    throw 'Diagnostic-setting capacity is exhausted. Ask an administrator to review existing settings; this script will not replace them.'
}
Write-Output "Add $Category for $AccountId to $WorkspaceResourceId in resource-specific mode."
Write-Output 'Existing exports are preserved. Review duplicate ingestion, retention and logging charges.'
Write-Output 'This enables only the named category; other detectors may need additional categories.'
if (-not $Apply) { Write-Output 'Preview only. Save and rerun with -Apply after review.'; return }
Assert-ReportedPermission $AccountId 'Microsoft.Insights/diagnosticSettings/write' $SubscriptionId
$name = 'coda-prechecks-' + [Guid]::NewGuid().ToString('N')
$url = "$base/diagnosticSettings/${name}?api-version=2021-05-01-preview"
$body = @{ properties = @{
    workspaceId = $WorkspaceResourceId
    logAnalyticsDestinationType = 'Dedicated'
    logs = @(@{ category = $Category; enabled = $true })
    metrics = @()
} } | ConvertTo-Json -Depth 8
$file = [IO.Path]::GetTempFileName()
try {
    [IO.File]::WriteAllText($file, $body, [Text.UTF8Encoding]::new($false))
    Invoke-AzJson @('rest','--method','put','--url',$url,'--body',"@$file",'--subscription',$SubscriptionId) | Out-Null
    $readback = Invoke-AzJson @('rest','--method','get','--url',$url,'--subscription',$SubscriptionId)
    if ($readback.properties.workspaceId -ine $WorkspaceResourceId -or
        $readback.properties.logAnalyticsDestinationType -ine 'Dedicated' -or
        -not @($readback.properties.logs | Where-Object { $_.enabled -and $_.category -ieq $Category }).Count) {
        throw "Readback is incomplete. Inspect setting $name before retrying."
    }
    Write-Output "Added $name. Collection begins prospectively; allow traffic and ingestion before rechecking."
} finally {
    Remove-Item -LiteralPath $file -ErrorAction Stop
}
"""
    )


def guidance(
    reader: ManagementReader, identity: dict | None, *, title: str, scope: str, summary: str,
    role: str | None = None, category: str | None = None, reason: str | None = None,
    admin_needed: bool = False,
) -> dict:
    """Offer scripts only with reported write authority and a known requester; otherwise route to admin."""
    action = DIAGNOSTIC_WRITE if category else ROLE_WRITE if role else None
    reported = reader.action(scope, action) if action is not None else "not_applicable"
    role_name = ROLES[role][0] if role else None
    requester = identity["object_id"] if identity else "Not verified; administrator must confirm the requester object ID"
    tenant = identity["tenant_id"] if identity else "Not verified"
    requirement = (
        f"{role_name} at {scope}" if role_name
        else f"Enable {category} in resource-specific mode with an approved Log Analytics workspace"
        if category else reason or "Review the observed read failure; no role assignment has been inferred."
    )
    admin = (
        f"CODA pre-check request\nRequester object ID: {requester}\nTenant: {tenant}\n"
        f"Scope: {scope}\nIssue: {summary}\nRequested review/change: {requirement}\n"
        f"Administrator operation required: {action or 'Investigate configuration/access policy'}\n"
        "Use least privilege and existing group/PIM processes. Do not grant administrator roles to CODA.\n"
        "Enabling diagnostics additionally needs read access to the selected workspace and may incur logging charges."
    )
    script = None
    if identity is not None and reported == "allowed":
        script = _logging_script(identity, scope, category) if category else _role_script(identity, scope, role) if role else None
    admin_message = (
        "Requester identity could not be verified. Ask your subscription administrator to confirm the requester and required access."
        if identity is None and action else
        f"The required administrative action ({action}) is not reported for your current identity at this scope. Ask your subscription administrator or a delegated scope administrator."
        if action and reported == "absent" else
        f"CODA could not verify the administrative action ({action}) at this scope. Ask your subscription administrator or a delegated scope administrator."
        if action and reported == "unknown" else
        "Ask your subscription administrator or an appropriately delegated scope administrator to review this request."
    )
    return {
        "title": title, "scope": scope, "summary": summary,
        "requester_object_id": identity["object_id"] if identity else None,
        "tenant_id": identity["tenant_id"] if identity else None,
        "required_role": role_name, "required_admin_action": action,
        "administrative_access": reported, "script": script, "admin_request": admin,
        "administrator_needed": bool(action or admin_needed),
        "message": (
            "Review the PowerShell below. It previews by default and changes Azure only when you run it with -Apply."
            if script else
            admin_message
            if action or admin_needed else reason or summary
        ),
        "caveat": _CAVEAT,
        "reason": reason,
    }

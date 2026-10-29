# Changelog

All notable changes to CODA are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.17.14] - 2026-10-28

### Preview status

- Source preparation for the next Preview, with cumulative customer-visible changes since
  public v0.17.12 Preview. Version 0.17.13 was not publicly released.
- Fresh all-detector live acceptance and signed-in Portal-link verification remain deferred.
  This source entry does not itself publish a tag or release.

### Added

- Detailed methodology for all 24 detectors, linked from the catalog and bundled with the package
  so agents can explain a finding offline.
- Setup guidance for VS Code/Copilot, Codex, Cursor and Claude Code using the same Python MCP
  server, plus an on-demand workflow for the finding's Agent Kit rule.
- Conditional Agent Kit investigation links for non-throttling error findings: dominant 404/409
  use `sdk-conditional-create-etag`; 412 uses `sdk-etag-concurrency`. Other statuses and
  non-findings remain unmapped, with no threshold, severity or telemetry changes.

### Fixed

- Autoscale right-sizing (DX-011) uses a minimum configurable maximum of 1,000 RU/s, which can
  scale down to 100 RU/s when idle. The manual-throughput minimum remains 400 RU/s.
- Recoverable autoscale capacity uses the 10%-of-maximum idle-floor reduction for both dedicated
  containers and shared databases. A 4,000 maximum peaking at 400 now has a 1,000 analytical
  target and 300 recoverable RU/s, rather than a false zero-recovery result.
- At the modeled minimum, autoscale guidance explains that no reduction is available instead of
  recommending an unchanged maximum.
- Expensive consistency (DX-016) now includes single-region Strong accounts at Medium severity
  because local quorum reads cost more RU, independently of cross-region write latency.
- Consistency guidance explains that "premium" is not a pricing SKU, and that Session can provide
  read-your-writes with the relevant session token. Each account has one default consistency
  level, Strong OR Bounded Staleness, not both. Reused SDK clients manage their tokens; for
  load-balanced web apps, flow the Cosmos response SessionToken through the web tier to the
  end-user cookie/client context, back on a later web request, then into the handling SDK's request
  options. Direct SDK-to-SDK synchronization is not required. Tokens stay opaque and partition-bound.
  Session does not replace Strong's global guarantees; review application requirements and read overrides.
- Error guidance no longer implies every non-429 failure is a client-side bug. 404s can be expected
  lookups, 412s can be preconditions working correctly, and 5xx can be service-side.
- Reserved-capacity guidance clarifies that Low severity is a reservation-review advisory even
  at 250,000 RU/s, not a judgment of low throughput/utilization or small savings. The proposed
  threshold and severity policy are unchanged; coverage and monetary savings are not measured.
- Packaged `explain_finding` no longer requires a source checkout. Broken methodology resources
  produce an explicit error rather than suggesting a known detector has no explanation.
- Package checks exercise actual catalog/explanation calls and compare the results with the wheel.

### Known limitations

- Autoscale targets remain analytical, not service-ready settings: accepted increments and
  resource-specific minimum maxima still require validation. A zero-recovery utilization signal
  can remain a Low finding; this is not guaranteed savings or an hourly bill simulation.
- Single-region Bounded Staleness policy is unchanged. Optional consistency read-charge enrichment
  remains an upper bound, not measured savings; missing logs do not suppress a configuration finding.
- Error rule links are conditional investigations, not evidence of a read-404-then-insert sequence,
  operation/item, missing concurrency control or hot item. Conditional-create examples are SDK-specific:
  .NET ignores `IfNoneMatchEtag` on writes, and unconditional upsert is not create-if-absent.
- Native offline MCP compatibility evidence was recorded for the preceding source with
  VS Code 1.144.0 and Codex 0.165.0. Cursor and Claude Code native runtime acceptance,
  model-provider/GUI flows and live Azure diagnostics remain unverified.
- Data sources, Azure permissions and diagnose-only operation are unchanged.

## [0.17.13] - 2026-10-28

### Preview status

- Source preparation only; this version was not publicly released. Its changes are included
  in the 0.17.14 preparation above.
- Cumulative customer-visible changes since public v0.17.12 Preview. This remains a Preview:
  fresh all-detector live acceptance and signed-in Portal-link verification remain deferred.

### Added

- Detailed methodology for all 24 detectors, linked from the catalog and bundled with the package
  so agents can explain a finding offline.
- Setup guidance for VS Code/Copilot, Codex, Cursor and Claude Code using the same Python MCP
  server, plus an on-demand workflow for the finding's Agent Kit rule.

### Fixed

- Packaged `explain_finding` no longer requires a source checkout. Broken methodology resources
  produce an explicit error rather than suggesting a known detector has no explanation.
- Package checks exercise actual catalog/explanation calls and compare the results with the wheel.

### Known limitations

- Native offline MCP calls were checked on Windows with VS Code 1.144.0 and Codex 0.165.0.
  Cursor and Claude Code native runtime acceptance, model-provider/GUI flows and live Azure
  diagnostics remain unverified. Configuration recipes do not certify every client/version.
- Detector behavior, data sources, Azure permissions and diagnose-only operation are unchanged.

## [0.17.12] - 2026-10-24

### Preview status

- Cumulative customer-visible changes since public v0.17.1 Preview. This remains a Preview:
  fresh all-detector live acceptance and signed-in Portal-link verification remain deferred.
  The intermediate source-preparation sections below are not separate public releases.

### Added

- DX-024 indexing cost risk: flags index/data storage ratios above 0.3 (Low) or 1.0 (Medium)
  across dedicated, shared-throughput and serverless NoSQL containers, without Log Analytics.
  Existing indexing exclusions remain evidence rather than suppressing the finding.

### Changed

- DX-002/DX-007 structural fan-out findings use physical partition count and query rate for
  severity, with a 0.1 query/second floor instead of a query-cost gate.
- Automatic installation selects the newest non-draft release including Previews, binds downloads
  to its tag and verifies checksums. GitHub Actions remain pinned to full commit SHAs.

### Fixed

- Partition-merge findings now distinguish structural over-partitioning from merge eligibility.
  Continuous backup (PITR) blocks merge and cannot be reverted to periodic backup on the existing
  account. Unknown or migrating backup state withholds merge instructions; periodic backup still
  requires the platform eligibility checker and SDK/connector checks.
- Optional full-fidelity change-feed enablement is recorded only when authoritative metadata
  supplies it, without inferring active usage. Fabric Mirroring is not assessed; no new permissions
  or feature-disabling recommendations are introduced.
- Shard-key misalignment uses unrounded measurements for boundary decisions. DX-017 retains its
  urgent High finding for a physical partition already at or above 50 GiB.
- Accounts exporting identical request logs to multiple workspaces no longer count each copy
  as additional activity.

### Known limitations

- Backup eligibility is not complete merge eligibility. Full-fidelity enablement is unknown when
  the management SDK/API omits it; active consumers and Fabric Mirroring are not discovered.
- Package/offline checks do not prove live detector correctness. No hosted service, automatic
  remediation, new Azure permissions or PyPI publication is introduced.

## [0.17.11] - 2026-10-24

### Fixed

- Shard-key misalignment decisions use precise fan-out measurements rather than rounded display
  values, preventing early findings and severity escalation immediately below the existing thresholds.
- Source preparation only; this entry does not publish or replace the v0.17.1 Preview release.

## [0.17.10] - 2026-10-24

### Changed

- Internal repository organization only; exported paths, diagnostic behavior, data sources,
  prerequisites and installation are unchanged.
- Source preparation only; this entry does not publish or replace the v0.17.1 Preview release.

## [0.17.9] - 2026-10-24

### Changed

- Internal integration CI maintenance only; no change to diagnostics, data sources,
  prerequisites or installation.
- Source preparation only; this entry does not publish or replace the v0.17.1 Preview release.

## [0.17.8] - 2026-10-24

### Changed

- Internal test maintenance only; no change to diagnostics, data sources, prerequisites or
  installation.
- Source preparation only; this entry does not publish or replace the v0.17.1 Preview release.

## [0.17.7] - 2026-10-23

### Added

- DX-024 (indexing cost risk): flags containers whose index storage is more than 30% of their
  data storage (Low), or larger than the data itself (Medium). It runs on every NoSQL container,
  including shared-throughput and serverless containers, and needs no Log Analytics. Paths you
  already excluded from indexing are reported as evidence.

### Changed

- DX-002 (cross-partition query fan-out) and DX-007 (shard-key misalignment) now flag fan-out by
  query pattern instead of query cost, because each partition visit adds cost and latency even
  when it is cheap. Fan-out below 0.1 queries per second is not reported. Severity depends on the
  number of physical partitions and the fan-out query rate.
- Source preparation only; this entry does not publish or replace the v0.17.1 Preview release.

### Fixed

- DX-017 keeps its urgent High finding when a physical partition is already at or above 50 GiB,
  even when another partition has a less urgent growth projection.
- Accounts that send diagnostic logs to more than one Log Analytics workspace no longer have
  their log-based totals counted once per workspace. Single-workspace accounts are unaffected.

## [0.17.3] - 2026-10-22

### Changed

- Preserve the full commit SHA pins for all GitHub Actions in package CI and release workflows
  when generating future public updates.
- Source preparation only; this entry does not publish or replace the v0.17.1 Preview release.

## [0.17.2] - 2026-10-17

### Changed

- Install the newest published release, including Previews, with copy-paste GitHub CLI instructions
  for PowerShell and Bash. Wheel and checksum downloads are pinned to one selected tag, and a
  failed download or checksum check stops installation.
- Keep manual downloads and version-pinned installation available. CI now guards the automatic
  installation examples against stale versions and missing checksum verification.

## [0.17.1] - 2026-10-17

### Preview status

- Changes since public v0.12.1. The release remains a Preview; complete live-detector acceptance
  and signed-in manual Portal-link verification remain separate requirements.

### Added

- **Five-minute log support:** DX-003 shared-throughput starvation, DX-010 uncontrolled ingestion,
  and optional DX-016 consistency read-charge enrichment prefer `CDBDataPlaneRequests5M`.
  Existing raw-log collection remains supported.
- **Run Pre-Checks:** check a selected account or NoSQL accounts in a resource group for ARM
  access, Resource Graph discovery, Azure Monitor metrics, Log Analytics configuration/data, and
  optional subscription Cost Management access without running a diagnosis.
- **Contextual fix dialogs:** copy scoped PowerShell or an administrator request containing the
  original requester and scope. Scripts preview by default and require explicit `-Apply` when
  run outside CODA; the app never executes them or changes Azure resources.
- README instructions mapping log-dependent detectors to required/optional sources, diagnostic
  categories, workspace table mode, read permissions, and collection prerequisites.

### Changed

- Five-minute queries use represented request counts and total RU, not aggregate row counts or
  unweighted averages. Reports retain the selected source and exact observation window.
- DX-010 labels five-minute burst evidence explicitly. Detection/severity thresholds are unchanged.
  Production aggregate windows retain a full day ending at a completed five-minute boundary.
- Resource Graph discovery uses the same SDK credential as diagnosis/pre-checks, replacing the
  independent CLI identity path.
- Pre-check results separate configuration, readable/recent data, and access/service errors.
  Configured/readable logs show green checks; observations use local time to the minute.
  Pre-check warnings do not prevent analysis with other available sources.

### Fixed

- Reports explain unavailable dollar savings, including Cost Management rate limiting, in the
  incomplete-results section. The account-level issue does not invalidate RU/s findings or
  increase detector/resource failure counts; JSON/MCP and group scans retain the reason.
- Missing log records, empty cost/metric data, and HTTP 429 responses no longer imply missing
  permissions. Suggested fixes preserve existing diagnostic exports and the original requester.
- Package verification supports deeply nested Windows paths without requiring a machine-wide
  long-path setting change. Python 3.12 bootstraps pip in isolation and reports bootstrap errors
  with their underlying output.

### Known limitations

- DX-002/DX-007 still require raw `CDBDataPlaneRequests` plus `CDBQueryRuntimeStatistics` for
  activity-level query cost/fan-out correlation; data-plane 5M logs cannot replace that evidence.
- Readable logs do not prove complete history or sufficient workload coverage. Local
  measurements are not a customer latency guarantee or full detector acceptance.
- No hosted CODA service, automatic remediation, or PyPI publication is introduced.

## [0.12.1] - 2026-10-13

### Preview status

- Published as a GitHub prerelease. Fresh all-detector live acceptance and signed-in Portal-link
  verification are deferred; package checks are not evidence that those checks passed.

### Added

- Getting-started instructions for release wheels, source checkouts, and local web/MCP use.
- Architecture, service/data-flow, least-privilege access, and Log Analytics setup documentation.
- A complete 23-detector reference with production windows, prerequisites, and limitations.
- A web UI screenshot with subscription and resource identifiers replaced by demo names.

### Changed

- Web scans require a selected resource group rather than scanning an entire subscription.
- Account results omit redundant metadata and remediation-rule links while preserving structured reports.
- Incomplete log-dependent checks link to resource-specific Log Analytics setup instructions.

## [0.12.0] - 2026-10-12

### Added

- GitHub Release distribution for the CODA wheel, including checksum verification guidance.
- Local web and optional MCP experiences for read-only Azure Cosmos DB diagnostics.
- Public security, support, feedback, and contribution guidance.
- Locked runtime and MCP constraint files generated from the public package metadata.

### Changed

- Finalized the supported local product and generated-release documentation for the first curated
  public distribution.

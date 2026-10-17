# Changelog

All notable changes to CODA are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  long-path setting change.

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

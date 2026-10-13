# Changelog

All notable changes to CODA are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

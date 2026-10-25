"""coda_core — the shared CODA diagnostics engine.

This package holds the data-source-agnostic core: detection windows, the
``DataProvider`` abstraction, and the concrete providers that read a customer's
own observability data (Azure Monitor Metrics, Log Analytics, ARM).

Design rule (do not violate): detection logic NEVER binds to a concrete data
source. Everything flows through ``coda_core.providers.base.DataProvider`` so the
local-user auth implementation and backing store (Metrics vs Log Analytics)
stay swappable.
"""

# Keep in sync with pyproject `version` and CHANGELOG.md on every PR.
APP_VERSION = "0.17.12"

"""CODA diagnostic pipeline: Select -> Detect -> Rollup -> Report (ADR-0007).

Public surface:
  * :func:`run_diagnostics` — run the full pipeline for one account.
  * :class:`DiagnosticReport`, :func:`render_markdown` — the structured result + renderer.
  * :class:`Finding` — the uniform per-detection output contract.
"""

from coda_core.pipeline.finding import Finding, UnitRef
from coda_core.pipeline.report import DiagnosticReport, render_markdown
from coda_core.pipeline.runner import default_eval_window, run_diagnostics

__all__ = [
    "run_diagnostics",
    "default_eval_window",
    "DiagnosticReport",
    "render_markdown",
    "Finding",
    "UnitRef",
]

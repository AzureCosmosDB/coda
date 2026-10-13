"""Detections — the ported, customer-data-source detection rules (DX-001..DX-010).

Each detection separates two concerns deliberately:
  * SIGNAL computation — deterministic measurement from telemetry (this is settled).
  * CLASSIFICATION/severity — mapping the signal to a verdict + priority. The
    methodology here (temporal percentile trigger + relative materiality severity)
    is under active research and is intentionally kept pluggable until agreed.
"""

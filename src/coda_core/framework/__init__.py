"""Cross-detection framework helpers (severity models, shared math).

These are deliberately small, dependency-light building blocks that more than one detection
needs — extracted only when a second consumer appeared (rule of three), to avoid premature
abstraction. The first member is :mod:`coda_core.framework.materiality` (cost-severity), shared
by DX-001 (right-size) and DX-004 (idle decommission).
"""

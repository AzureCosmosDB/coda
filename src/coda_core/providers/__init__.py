"""Data providers: the swappable seam between detection logic and telemetry.

`base` defines the abstract contract and shared value types (TimeWindow, etc.).
Concrete providers (`azure_monitor`, `log_analytics`) implement it against a
customer's own observability data.
"""

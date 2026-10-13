"""Packaged MCP adapter for CODA's customer-safe diagnostic tools.

The optional ``mcp`` dependency is imported only while building a server. The installed server
never updates its wheel in place and omits the internal checkout-only ``update`` tool.
"""

from __future__ import annotations

from coda_core import mcp_tools


def build_server(*, include_update_tool: bool = False):
    """Build the stdio MCP server, optionally adding the internal checkout update tool."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("coda")

    if include_update_tool:
        from coda_core.selfupdate import update_report

        @server.tool()
        def update() -> dict:
            """Update a public-release checkout, then restart the MCP server."""
            return update_report()

    @server.tool()
    def list_detectors() -> dict:
        """List every diagnostic CODA can run and the data each one requires."""
        return mcp_tools.list_detectors()

    @server.tool()
    def explain_finding(detection_id: str) -> dict:
        """Explain a detection's methodology and thresholds."""
        return mcp_tools.explain_finding(detection_id)

    @server.tool()
    def scan_subscription(
        subscription: str,
        resource_groups: list[str] | None = None,
        accounts: list[str] | None = None,
        mode: str = "production",
        concurrency: int = 8,
        per_account_timeout: float = 120.0,
        limit: int | None = None,
        redact: bool = False,
    ) -> dict:
        """Scan a subscription and return its aggregated diagnostic findings."""
        return mcp_tools.scan_subscription(
            subscription,
            resource_groups=resource_groups,
            accounts=accounts,
            mode=mode,
            concurrency=concurrency,
            per_account_timeout=per_account_timeout,
            limit=limit,
            redact=redact,
        )

    @server.tool()
    def diagnose_account(
        subscription: str,
        resource_group: str,
        account: str,
        mode: str = "production",
        eval_hours: int | None = None,
        redact: bool = False,
        unit_concurrency: int | None = None,
    ) -> dict:
        """Diagnose one account in depth and return its structured report."""
        return mcp_tools.diagnose_account(
            subscription,
            resource_group,
            account,
            mode=mode,
            eval_hours=eval_hours,
            redact=redact,
            unit_concurrency=unit_concurrency,
        )

    @server.tool()
    def scan_subscription_shallow(
        subscription: str,
        resource_groups: list[str] | None = None,
        accounts: list[str] | None = None,
        window_hours: int = 24,
        concurrency: int = 32,
        limit: int | None = None,
    ) -> dict:
        """Return fast account-level health signals for a subscription."""
        return mcp_tools.scan_subscription_shallow(
            subscription,
            resource_groups=resource_groups,
            accounts=accounts,
            window_hours=window_hours,
            concurrency=concurrency,
            limit=limit,
        )

    @server.tool()
    def diagnose_account_shallow(
        subscription: str,
        resource_group: str,
        account: str,
        window_hours: int = 24,
    ) -> dict:
        """Return a fast account-level health signal without Log Analytics."""
        return mcp_tools.diagnose_account_shallow(
            subscription,
            resource_group,
            account,
            window_hours=window_hours,
        )

    return server


def main() -> None:
    """Serve the packaged, non-self-updating MCP surface over stdio."""
    build_server(include_update_tool=False).run()


__all__ = ["build_server", "main"]

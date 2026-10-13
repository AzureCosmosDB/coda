"""Installed CODA command line entry point for the public web and MCP surfaces."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

_MISSING_MCP_MESSAGE = (
    'coda mcp needs the optional "mcp" extra, which is not installed. Reinstall the CODA wheel '
    'you installed with the extra, for example: pip install "coda[mcp] @ '
    '<path-or-URL-of-that-wheel>" (see README "Install"). PyPI publication is not available.'
)


def _parser() -> argparse.ArgumentParser:
    """Build the stable two-command public CLI without importing either optional server runtime."""
    parser = argparse.ArgumentParser(
        prog="coda",
        description="Run CODA's customer-safe web or MCP diagnostic surface.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    web = commands.add_parser("web", help="Run the local customer-safe web application.")
    web.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    web.add_argument("--port", default=8000, type=int, help="Bind port (default: 8000).")

    commands.add_parser("mcp", help="Run the customer-safe MCP server over stdio.")
    return parser


def _run_web(host: str, port: int) -> int:
    """Run the public app in factory form so importing it never creates a module-level app."""
    import uvicorn

    uvicorn.run(
        "coda_web.public_app:create_public_app",
        factory=True,
        host=host,
        port=port,
    )
    return 0


def _run_mcp() -> int:
    """Load the optional MCP surface only when requested and explain how to add it safely."""
    try:
        from coda_core import mcp_server

        mcp_server.main()
    except ModuleNotFoundError as exc:
        if exc.name != "mcp" and not (exc.name or "").startswith("mcp."):
            raise
        print(_MISSING_MCP_MESSAGE, file=sys.stderr)
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the installed ``coda`` command to its selected customer-safe surface."""
    args = _parser().parse_args(argv)
    if args.command == "web":
        return _run_web(args.host, args.port)
    return _run_mcp()


__all__ = ["main"]

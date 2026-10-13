"""Offline tests for packaging and CLI boundaries, not Azure telemetry or detections."""

from __future__ import annotations

import ast
import builtins
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from coda_core import cli

pytestmark = pytest.mark.public

_ROOT = Path(__file__).resolve().parents[1]
_CLI_SOURCE = _ROOT / "src" / "coda_core" / "cli.py"
_MCP_SOURCE = _ROOT / "src" / "coda_core" / "mcp_server.py"


def _tree(path: Path) -> ast.Module:
    """Parse a shipped module without importing its optional dependencies."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_cli_help_lists_web_and_mcp(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "web" in help_text
    assert "mcp" in help_text


def test_cli_and_mcp_server_do_not_import_mcp_at_module_scope():
    for path in (_CLI_SOURCE, _MCP_SOURCE):
        imports = [
            node
            for node in _tree(path).body
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        assert not any(
            (
                isinstance(node, ast.Import)
                and any(alias.name == "mcp" or alias.name.startswith("mcp.") for alias in node.names)
            )
            or (
                isinstance(node, ast.ImportFrom)
                and (node.module == "mcp" or (node.module or "").startswith("mcp."))
            )
            for node in imports
        ), f"{path} imports the optional mcp distribution at module scope"


def test_missing_mcp_extra_exits_nonzero_with_release_asset_guidance(monkeypatch, capsys):
    real_import = builtins.__import__

    def reject_mcp(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "mcp" or name.startswith("mcp."):
            error = ModuleNotFoundError("No module named 'mcp'")
            error.name = "mcp"
            raise error
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", reject_mcp)

    assert cli.main(["mcp"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert 'coda[mcp] @ <path-or-URL-of-that-wheel>' in captured.err
    assert "PyPI publication is not available" in captured.err
    assert "Traceback" not in captured.err


def test_web_subcommand_uses_factory_form_on_loopback(monkeypatch):
    calls: list[tuple[tuple, dict]] = []
    fake_uvicorn = SimpleNamespace(run=lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)

    assert cli.main(["web"]) == 0
    assert calls == [
        (
            ("coda_web.public_app:create_public_app",),
            {"factory": True, "host": "127.0.0.1", "port": 8000},
        )
    ]


def test_packaged_mcp_server_never_self_updates():
    tree = _tree(_MCP_SOURCE)
    references = [
        node
        for node in ast.walk(tree)
        if (isinstance(node, ast.Name) and node.id == "auto_update")
        or (isinstance(node, ast.Attribute) and node.attr == "auto_update")
    ]
    assert references == []

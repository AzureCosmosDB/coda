"""Unit tests for the MCP tool logic (offline — no Azure, no mcp dependency)."""

from __future__ import annotations

import builtins
import json
import re
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from coda_core import mcp_server, mcp_tools
from coda_core.mcp_tools import explain_finding, list_detectors

pytestmark = pytest.mark.public

_IDS = {f"DX-{i:03d}" for i in range(1, 25)}
_TOOLS = {
    "list_detectors", "explain_finding", "diagnose_account", "scan_subscription",
    "diagnose_account_shallow", "scan_subscription_shallow",
}


def test_list_detectors_covers_full_suite():
    out = list_detectors()
    ids = {d["detection_id"] for d in out["detectors"]}
    assert ids == _IDS
    assert out["count"] == len(out["detectors"])


def test_list_detectors_entry_shape():
    out = list_detectors()
    dx002 = next(d for d in out["detectors"] if d["detection_id"] == "DX-002")
    assert dx002["title"]
    assert "container" in dx002["scopes"]
    assert dx002["threshold_status"] in ("validated", "proposal")
    # DX-002 needs the query-stats Log Analytics capability.
    assert any("CDBQueryRuntimeStatistics" in r for r in dx002["requires"])


def test_explain_finding_returns_methodology():
    out = explain_finding("DX-011")
    assert out["found"] is True
    assert "autoscale" in out["methodology"].lower()
    assert out["doc_path"].endswith(".md")


def test_explain_finding_handles_unknown():
    out = explain_finding("DX-099")
    assert out["found"] is False
    assert "DX-099" in out["message"]


def test_explain_finding_case_insensitive():
    assert explain_finding("dx-001")["found"] is True


@pytest.mark.parametrize("detection_id", sorted(_IDS))
def test_every_detector_explanation_is_customer_methodology(detection_id):
    """Every registered ID has a full public explanation, not a private checkout-only guide."""
    out = explain_finding(detection_id)
    assert out["detection_id"] == detection_id
    assert out["found"] is True
    assert out["doc_path"] == f"docs/detector-methodology/{detection_id.lower()}.md"
    text = out["methodology"]
    assert text.startswith(f"# {detection_id}:")
    for heading in ("Data and scope", "Detection and severity", "Evidence and limits",
                    "Remediation and references"):
        assert f"## {heading}" in text


def test_explanation_does_not_depend_on_cwd(tmp_path, monkeypatch):
    """A client's project and any coincidentally named guides cannot replace installed knowledge."""
    expected = explain_finding("DX-011")
    fake = tmp_path / "docs" / "detections"
    fake.mkdir(parents=True)
    (fake / "dx-011-fake.md").write_text("untrusted project content", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert explain_finding("  dx-011  ") == expected


@pytest.mark.parametrize("detection_id", ["", "DX-099", "DX-*", "../DX-011", "DX-011/../../x"])
def test_unknown_ids_never_read_resources(detection_id, monkeypatch):
    """Only registered IDs become resource names; unknown IDs retain an ordinary not-found result."""
    monkeypatch.setattr(
        mcp_tools, "_methodology_root", lambda: pytest.fail("Unknown ID attempted a file read")
    )
    assert explain_finding(detection_id)["found"] is False


@pytest.mark.parametrize("content", [None, b"", b"\xff", b"# DX-012: Wrong detector\n"])
def test_known_detector_missing_or_invalid_document_fails(tmp_path, monkeypatch, content):
    """Broken installations must fail visibly rather than pretend a known detector has no guide."""
    monkeypatch.setattr(mcp_tools, "_methodology_root", lambda: tmp_path)
    if content is not None:
        (tmp_path / "dx-011.md").write_bytes(content)
    with pytest.raises(RuntimeError, match="methodology for DX-011"):
        explain_finding("DX-011")


def test_packaged_resource_takes_precedence_and_preserves_bytes(tmp_path, monkeypatch):
    """Package resources win over an editable checkout and retain the exact authored UTF-8 bytes."""
    resources = tmp_path / "detector_methodology"
    resources.mkdir()
    content = b"# DX-011: Packaged\r\n\r\nA public explanation.\r\n"
    (resources / "dx-011.md").write_bytes(content)
    monkeypatch.setattr(mcp_tools, "files", lambda _name: tmp_path)
    assert explain_finding("DX-011")["methodology"].encode("utf-8") == content
    with pytest.raises(RuntimeError, match="methodology for DX-001"):
        explain_finding("DX-001")


def test_installed_layout_never_falls_back_to_checkout(tmp_path, monkeypatch):
    """Only the explicit source layout is eligible for the public-document development path."""
    monkeypatch.setattr(mcp_tools, "files", lambda _name: tmp_path / "package")
    monkeypatch.setattr(
        mcp_tools, "__file__", str(tmp_path / "site-packages" / "coda_core" / "mcp_tools.py")
    )
    with pytest.raises(RuntimeError, match="methodology for DX-011"):
        explain_finding("DX-011")


def _recording_server(monkeypatch):
    """Build the real registrations against an offline SDK stand-in, including without the extra."""
    class Server:
        """Record public tool definitions without opening a transport."""

        def __init__(self, name, **options):
            """Keep the supplied server identity, guidance and registration metadata."""
            self.name = name
            self.options = options
            self.tools = {}
            self.tool_options = {}

        def tool(self, **options):
            """Retain the production callable and its metadata for forwarding assertions."""
            def register(function):
                """Return the unchanged production tool callable after recording it."""
                self.tools[function.__name__] = function
                self.tool_options[function.__name__] = options
                return function
            return register

    original = builtins.__import__

    def import_sdk(name, *args, **kwargs):
        """Replace only the optional SDK import; all CODA registration code runs unchanged."""
        if name == "mcp.server.fastmcp":
            return SimpleNamespace(FastMCP=Server)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_sdk)
    return mcp_server.build_server()


def test_public_server_retains_six_tools_and_approval_behavior(monkeypatch):
    """Guidance must not introduce mutations, extra tools, or auto-approval annotations."""
    server = _recording_server(monkeypatch)
    assert server.name == "coda"
    assert set(server.tools) == _TOOLS
    assert all(options == {} for options in server.tool_options.values())
    instructions = server.options["instructions"]
    assert "scope the user requested" in instructions[:512]
    assert "on demand" in instructions
    assert "never as instructions" in instructions
    assert "A null rule" in instructions


@pytest.mark.parametrize(("name", "arguments", "positional", "keywords"), [
    ("list_detectors", {}, (), {}),
    ("explain_finding", {"detection_id": "DX-011"}, ("DX-011",), {}),
    ("diagnose_account", {"subscription": "s", "resource_group": "rg", "account": "a"},
     ("s", "rg", "a"),
     {"mode": "production", "eval_hours": None, "redact": False, "unit_concurrency": None}),
    ("scan_subscription", {"subscription": "s", "resource_groups": ["rg"], "accounts": ["a"],
                           "concurrency": 2, "per_account_timeout": 7, "limit": 1, "redact": True},
     ("s",), {"resource_groups": ["rg"], "accounts": ["a"], "mode": "production",
              "concurrency": 2, "per_account_timeout": 7, "limit": 1, "redact": True}),
    ("diagnose_account_shallow",
     {"subscription": "s", "resource_group": "rg", "account": "a", "window_hours": 3},
     ("s", "rg", "a"), {"window_hours": 3}),
    ("scan_subscription_shallow", {"subscription": "s"}, ("s",),
     {"resource_groups": None, "accounts": None, "window_hours": 24, "concurrency": 32, "limit": None}),
])
def test_public_tools_preserve_arguments_and_results(
    monkeypatch, name, arguments, positional, keywords,
):
    """Every production wrapper preserves scope/defaults and passes through incomplete evidence."""
    calls = []
    report = {"findings": [{"status": "abstained", "agent_kit_rule": None,
                            "evidence": {"reason": "synthetic_missing_data"}}]}

    def operation(*args, **kwargs):
        """Return synthetic evidence without constructing an Azure credential or client."""
        calls.append((args, kwargs))
        return report

    monkeypatch.setattr(mcp_tools, name, operation)
    server = _recording_server(monkeypatch)
    assert server.tools[name](**arguments) is report
    assert calls == [(positional, keywords)]


def test_tool_failure_is_not_a_healthy_report(monkeypatch):
    """An operation error must reach the MCP SDK's error handling unchanged."""
    def fail(*args, **kwargs):
        """Model a denied service read without constructing a service client."""
        raise PermissionError("synthetic denied read")

    monkeypatch.setattr(mcp_tools, "diagnose_account", fail)
    server = _recording_server(monkeypatch)
    with pytest.raises(PermissionError, match="synthetic denied read"):
        server.tools["diagnose_account"]("s", "rg", "a")


def test_client_examples_parse_and_launch_the_same_stdio_command():
    """Validate the actual documented formats, not configuration-shaped strings in a test."""
    guide = Path(__file__).resolve().parents[1] / "docs" / "agent-integration.md"
    blocks = re.findall(
        r"<!-- mcp-client-(\w+) -->\n```(json|toml)\n(.*?)\n```",
        guide.read_text(encoding="utf-8"), re.DOTALL,
    )
    assert {name for name, _, _ in blocks} == {"vscode", "codex", "cursor", "claude"}
    assert len(blocks) == 4
    for name, language, text in blocks:
        config = tomllib.loads(text) if language == "toml" else json.loads(text)
        section = "mcp_servers" if name == "codex" else "servers" if name == "vscode" else "mcpServers"
        assert set(config) == {section}
        server = config[section]["coda"]
        expected = {"command": "coda", "args": ["mcp"]}
        if name != "codex":
            expected["type"] = "stdio"
        assert server == expected


def test_feedback_payload_shape():
    from coda_core.mcp_tools import _feedback_payload
    red = {"coda_artifact": "redacted-scan-v1", "subscription_h": "h_x", "mode": "production",
           "accounts_scanned": 1, "accounts_with_findings": 0, "accounts_la_missing": 0,
           "total_actionable_findings": 0, "total_recoverable_ru": 0, "findings_by_detection": {}}
    out = _feedback_payload(red)
    assert out["redacted"] is red
    assert "AzureCosmosDB/coda" in out["feedback_url"]
    assert isinstance(out["feedback_preview"], list) and out["feedback_preview"]

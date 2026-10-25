"""Verify public packaging, installation guidance, and routes, not Azure telemetry or detections."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.routing import Mount
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient

from coda_web import public_app
from coda_web.public_app import create_public_app

pytestmark = pytest.mark.public

_STRUCTURAL_TOKENS = (
    "resourceMode",
    "isFixture",
    "fixtureActive",
    "CODA_DEFAULT_SUBSCRIPTION",
    "showAllSubscriptions",
    "generateLoad",
    "loadgen",
    "scenarios.json",
    'name="mode"',
    'value="eval"',
    'name="depth"',
    'value="shallow"',
)


def _latest_install_examples() -> dict[str, str]:
    """Read the actual install commands in either the authoritative or exported README layout."""
    root = Path(__file__).resolve().parents[1]
    source = root / "release" / "public" / "governance" / "README.md"
    readme = (source if source.is_file() else root / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(
        r"<!-- latest-release-(powershell|bash) -->\n```(?:powershell|bash)\n(.*?)\n```",
        readme, re.DOTALL,
    )
    assert len(blocks) == 2 and {shell for shell, _ in blocks} == {"powershell", "bash"}
    return dict(blocks)


@pytest.mark.parametrize("shell", ["powershell", "bash"])
def test_latest_install_selects_published_preview_and_verifies_before_install(shell):
    """Every public PR guards the version-free selector and same-tag, fail-closed install order."""
    script = _latest_install_examples()[shell]
    selector = next(line for line in script.splitlines() if "gh release list " in line)
    for flag in ("--exclude-drafts", "--order desc", "--limit 1", "--json tagName",
                 "--jq '.[0].tagName'"):
        assert flag in selector
    assert "AzureCosmosDB/coda" in script
    assert "--exclude-pre-releases" not in script
    assert "/releases/latest" not in script
    assert not re.search(r"\bv?\d+\.\d+\.\d+\b", script), "Do not pin automatic installs."
    download = next(line for line in script.splitlines() if line.startswith("gh release download "))
    assert re.search(r'gh release download "?\$tag"? ', download)
    assert "--pattern SHA256SUMS.txt" in download
    assert re.search(r'--pattern "?\$wheel"? ', download)
    assert '"coda-$version-py3-none-any.whl"' in script
    assert "--clobber" not in script
    check = script.index("python -c ")
    install = script.index('python -m pip install "./$wheel"')
    assert script.index("gh release download ") < check < install
    if shell == "powershell":
        assert "IsNullOrWhiteSpace($tag)" in script
        assert "$version = $tag -replace '^v', ''" in script
        assert 'if ($LASTEXITCODE -ne 0)' in script[script.index("gh release download "):check]
        assert "throw " in script[script.index("gh release download "):check]
        assert 'if ($LASTEXITCODE -ne 0)' in script[check:install]
        assert "throw " in script[check:install]
    else:
        assert script.startswith("set -euo pipefail\n")
        assert 'version="${tag#v}"' in script
        assert 'test -n "$tag"' in script
        assert "|| true" not in script


@pytest.mark.parametrize("shell", ["powershell", "bash"])
@pytest.mark.parametrize("case", ["valid", "tampered", "missing-wheel", "missing-checksums", "missing-entry"])
def test_documented_checksum_command_rejects_unverified_wheels(tmp_path, shell, case):
    """Execute the README's real checksum code offline, including corruption and missing inputs."""
    script = _latest_install_examples()[shell]
    line = next(line for line in script.splitlines() if line.startswith("python -c "))
    code = shlex.split(line)[2]
    wheel = tmp_path / "coda-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"synthetic release wheel")
    checksums = tmp_path / "SHA256SUMS.txt"
    checksums.write_text(
        f"{hashlib.sha256(wheel.read_bytes()).hexdigest()}  {wheel.name}\n", encoding="utf-8",
    )
    if case == "tampered":
        wheel.write_bytes(b"changed after publication")
    elif case == "missing-wheel":
        wheel.unlink()
    elif case == "missing-checksums":
        checksums.unlink()
    elif case == "missing-entry":
        checksums.write_text(f"{'0' * 64}  unrelated.whl\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, wheel.name],
        cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False,
    )
    assert (result.returncode == 0) == (case == "valid")
    if case == "valid":
        assert "SHA-256 verified" in result.stdout


def test_public_app_import_graph_excludes_internal_modules():
    """A fresh public-app import excludes hosted and fixture-only module namespaces."""
    script = (
        "import json, sys\n"
        "import coda_web.public_app\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=120,
        env=os.environ.copy(),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    modules = json.loads(result.stdout)
    forbidden = ("internal", "loadgen", "coda_web.loadgen", "coda_web.auth", "coda_web.app")
    offenders = {
        prefix: [
            module
            for module in modules
            if module == prefix or module.startswith(prefix + ".")
        ]
        for prefix in forbidden
    }
    assert not {prefix: found for prefix, found in offenders.items() if found}


def test_retired_hosted_modules_are_absent_without_repository_internal_path():
    """The public source tree has no compatibility module for the retired hosted adapter."""

    src = Path(__file__).resolve().parents[1] / "src"
    script = (
        "import importlib.util, json, sys\n"
        f"sys.path.insert(0, {str(src)!r})\n"
        "names = ('coda_web.app', 'coda_web.auth', 'coda_web.settings')\n"
        "print(json.dumps([name for name in names if importlib.util.find_spec(name)]))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=src,
        capture_output=True,
        text=True,
        timeout=120,
        env=os.environ.copy(),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


def test_public_fixture_routes_404_and_index_200():
    """Fixture routes remain absent while the customer index remains available."""
    with TestClient(create_public_app()) as client:
        assert client.get("/api/loadgen").status_code == 404
        assert client.get("/api/loadgen/start").status_code == 404
        assert client.get("/").status_code == 200


def test_exactly_one_static_mount_registered_last():
    """The one catch-all static mount is registered after every API route."""
    app = create_public_app()
    mounts = [
        route
        for route in app.routes
        if isinstance(route, Mount) and isinstance(route.app, StaticFiles)
    ]
    assert len(mounts) == 1
    assert app.routes[-1] is mounts[0]


def test_public_static_assets_have_no_fixture_controls():
    """Customer package sources contain none of the fixture-control structural tokens."""
    module_path = Path(public_app.__file__).resolve()
    scanned = [module_path]
    scanned.extend(
        sorted(path for path in module_path.with_name("public_static").rglob("*") if path.is_file())
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in scanned)
    assert [token for token in _STRUCTURAL_TOKENS if token in combined] == []

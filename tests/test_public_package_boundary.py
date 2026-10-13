"""Verify public packaging and route boundaries, not Azure telemetry or detections."""

from __future__ import annotations

import json
import os
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

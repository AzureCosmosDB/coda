"""Smoke the installed public wheel through its real ``coda`` entry points.

This script intentionally uses only the Python standard library so it can run on a clean
Windows, macOS, or Linux GitHub runner before any project dependency is installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import venv
import zipfile
from pathlib import Path
from typing import BinaryIO

_EXPECTED_TOOLS = {
    "diagnose_account",
    "diagnose_account_shallow",
    "explain_finding",
    "list_detectors",
    "scan_subscription",
    "scan_subscription_shallow",
}
_EXPECTED_DETECTORS = {f"DX-{number:03d}" for number in range(1, 25)}
_METHODOLOGY_PREFIX = "coda_core/detector_methodology/"
PUBLIC_INDEX_URL = "https://pypi.org/simple"


class SmokeError(RuntimeError):
    """Report a public artifact smoke failure with an actionable message."""


class IndexPreflightError(SmokeError):
    """Report public-index reachability separately from artifact failures."""

    def __init__(self, category: str, detail: str) -> None:
        super().__init__(f"public index preflight failed ({category}): {detail}")
        self.category = category


def preflight_public_index(
    url: str = PUBLIC_INDEX_URL,
    *,
    timeout: float = 20,
) -> dict[str, object]:
    """Prove the exact public package index is reachable with verified TLS."""
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=ssl.create_default_context(),
        ) as response:
            return {
                "index_url": url,
                "resolved_url": response.geturl(),
                "status": response.status,
                "tls": ssl.OPENSSL_VERSION,
            }
    except urllib.error.HTTPError as exc:
        raise IndexPreflightError("http", f"HTTP {exc.code} from {url}") from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        category = "tls" if isinstance(reason, ssl.SSLError) else "network"
        raise IndexPreflightError(category, str(reason)) from exc
    except ssl.SSLError as exc:
        raise IndexPreflightError("tls", str(exc)) from exc
    except (TimeoutError, OSError) as exc:
        raise IndexPreflightError("network", str(exc)) from exc


def find_single_wheel(dist: Path) -> Path:
    """Return the sole wheel in ``dist`` and reject ambiguous artifact sets."""
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise SmokeError(f"expected exactly one wheel in {dist}, found {len(wheels)}")
    return wheels[0].resolve()


def assert_wheel_contents(wheel: Path) -> dict[str, str]:
    """Require public files and return the exact methodology for subsequent wire comparison."""
    required = {
        "coda_core/cli.py",
        "coda_core/mcp_server.py",
        "coda_web/public_app.py",
    }
    forbidden = {
        "coda_web/app.py",
        "coda_web/auth.py",
        "coda_web/settings.py",
    }
    with zipfile.ZipFile(wheel) as archive:
        names = {name.replace("\\", "/") for name in archive.namelist()}
        methodology_bytes = {
            name.replace("\\", "/"): archive.read(name) for name in archive.namelist()
            if name.replace("\\", "/").startswith(_METHODOLOGY_PREFIX)
        }
    missing = required - names
    if missing:
        raise SmokeError(f"wheel omitted required public files: {sorted(missing)}")
    offenders = sorted(
        name
        for name in names
        if name in forbidden
        or name.startswith(("internal/", "loadgen/"))
        or name == "scripts/mcp_server.py"
    )
    if offenders:
        raise SmokeError(f"wheel contains private/internal files: {offenders}")
    entry_points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
    if len(entry_points) != 1:
        raise SmokeError(f"wheel must contain one entry_points.txt, found {len(entry_points)}")
    expected_paths = {
        f"{_METHODOLOGY_PREFIX}{did.lower()}.md" for did in _EXPECTED_DETECTORS
    }
    if set(methodology_bytes) != expected_paths:
        raise SmokeError("wheel methodology must contain exactly the 24 registered detector pages")
    methodology = {}
    for did in sorted(_EXPECTED_DETECTORS):
        try:
            text = methodology_bytes[f"{_METHODOLOGY_PREFIX}{did.lower()}.md"].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SmokeError(f"wheel methodology is not UTF-8 for {did}") from exc
        if not text.startswith(f"# {did}:"):
            raise SmokeError(f"wheel methodology has the wrong detector header for {did}")
        methodology[did] = text
    return methodology


def venv_paths(root: Path, *, platform: str | None = None) -> tuple[Path, Path]:
    """Return the interpreter and ``coda`` launcher paths for the target platform."""
    platform = platform or sys.platform
    if platform == "win32":
        return root / "Scripts" / "python.exe", root / "Scripts" / "coda.exe"
    return root / "bin" / "python", root / "bin" / "coda"


def find_free_port() -> int:
    """Reserve and return an available loopback TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def matches_missing_extra_message(result: subprocess.CompletedProcess[str]) -> bool:
    """Recognize the required actionable failure from ``coda mcp`` without its extra."""
    return result.returncode != 0 and "coda[mcp] @" in (result.stdout + result.stderr)


def jsonrpc_line(message: dict) -> bytes:
    """Encode one MCP stdio JSON-RPC message using newline-delimited framing."""
    return json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"


def read_jsonrpc_line(stream: BinaryIO) -> dict:
    """Read and decode one newline-delimited MCP stdio JSON-RPC message."""
    line = stream.readline()
    if not line:
        raise SmokeError("MCP server closed stdout before replying")
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SmokeError(f"invalid MCP JSON-RPC response: {line!r}") from exc
    if not isinstance(message, dict):
        raise SmokeError(f"MCP JSON-RPC response is not an object: {message!r}")
    return message


def constraint_paths(dist: Path, *, no_constraints: bool) -> tuple[Path | None, Path | None]:
    """Resolve required runtime/MCP constraints unless the caller explicitly disables them."""
    if no_constraints:
        return None, None
    runtime = dist / "constraints-runtime.txt"
    mcp = dist / "constraints-mcp.txt"
    missing = [str(path) for path in (runtime, mcp) if not path.is_file()]
    if missing:
        raise SmokeError(f"missing required constraint file(s): {', '.join(missing)}")
    return runtime.resolve(), mcp.resolve()


def _run(
    command: list[str],
    *,
    timeout: float = 300,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a child command and include captured output in any failure."""
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        raise SmokeError(
            f"command failed ({result.returncode}): {command!r}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def resolved_venv_path(root: Path) -> Path:
    """Use one absolute path representation for deep installs and interpreter provenance checks."""
    root = root.resolve()
    if os.name == "nt":
        absolute = str(root)
        if not absolute.startswith("\\\\?\\"):
            absolute = (
                "\\\\?\\UNC\\" + absolute[2:] if absolute.startswith("\\\\")
                else "\\\\?\\" + absolute
            )
        root = Path(absolute)
    return root


def _create_venv(root: Path) -> tuple[Path, Path]:
    """Bootstrap pip in isolation so older bundles do not scan invalid extended-path cwd entries."""
    root = resolved_venv_path(root)
    venv.EnvBuilder(with_pip=False, clear=True).create(root)
    python, coda = venv_paths(root)
    if not python.is_file():
        raise SmokeError(f"virtual-environment interpreter missing: {python}")
    _run([str(python), "-I", "-m", "ensurepip", "--upgrade", "--default-pip"])
    return python, coda


def _install(
    python: Path,
    requirement: str,
    constraint: Path | None,
    *,
    wheelhouse: Path | None = None,
) -> None:
    """Install the exact local wheel from PyPI or a caller-populated offline wheelhouse."""
    command = [
        str(python),
        "-m",
        "pip",
        "--isolated",
        "--disable-pip-version-check",
        "install",
    ]
    if wheelhouse is None:
        command.extend(["--index-url", PUBLIC_INDEX_URL])
    else:
        command.extend(["--no-index", "--find-links", str(wheelhouse)])
    command.append(requirement)
    if constraint is not None:
        command.extend(["-c", str(constraint)])
    child_env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("PIP_", "UV_INDEX"))
        and key.upper() not in {"UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_FIND_LINKS"}
    }
    _run(command, env=child_env)


def _assert_private_imports_absent(python: Path, workdir: Path) -> None:
    """Prove private namespaces cannot be imported from the installed public wheel."""
    modules = ("internal", "loadgen", "coda_web.auth", "coda_web.app", "coda_web.settings")
    script = (
        "import importlib.util, json\n"
        f"modules = {modules!r}\n"
        "found = [name for name in modules if importlib.util.find_spec(name) is not None]\n"
        "print(json.dumps(found))\n"
        "raise SystemExit(bool(found))\n"
    )
    result = subprocess.run(
        [str(python), "-I", "-c", script],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise SmokeError(f"installed wheel exposes private modules: {result.stdout.strip()}")


def _stop_process(process: subprocess.Popen, *, timeout: float = 10) -> None:
    """Terminate one recorded process id, escalating to kill only after the grace period."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)
    if process.poll() is None:
        raise SmokeError(f"process {process.pid} did not exit")


def _poll_web(port: int, process: subprocess.Popen, *, timeout: float = 90) -> str:
    """Poll the public index until HTTP 200 or until the process/deadline fails."""
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/"
    last_error = "no response"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SmokeError(f"coda web exited before becoming ready ({process.returncode})")
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                body = response.read().decode("utf-8", errors="replace")
                if response.status == 200:
                    return body
                last_error = f"HTTP {response.status}"
        except (OSError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise SmokeError(f"coda web did not return HTTP 200 within {timeout:g}s: {last_error}")


def _reader(stream: BinaryIO, messages: queue.Queue[object]) -> None:
    """Transfer MCP stdout messages to a deadline-aware queue."""
    try:
        while True:
            messages.put(read_jsonrpc_line(stream))
    except BaseException as exc:
        messages.put(exc)


def _response(messages: queue.Queue[object], request_id: int, *, timeout: float = 30) -> dict:
    """Wait for the JSON-RPC response matching ``request_id`` while ignoring notifications."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeError(f"timed out waiting for MCP response id {request_id}")
        try:
            message = messages.get(timeout=remaining)
        except queue.Empty as exc:
            raise SmokeError(f"timed out waiting for MCP response id {request_id}") from exc
        if isinstance(message, BaseException):
            raise SmokeError(f"MCP stdout reader failed: {message}") from message
        if message.get("id") == request_id:
            if "error" in message:
                raise SmokeError(f"MCP request {request_id} failed: {message['error']}")
            return message


def _write_jsonrpc(stream: BinaryIO, message: dict) -> None:
    """Write and flush one JSON-RPC request to MCP stdio."""
    stream.write(jsonrpc_line(message))
    stream.flush()


def _tool_payload(response: dict) -> dict:
    """Decode standard JSON text or structured MCP output, rejecting tool errors and bad shapes."""
    result = response.get("result")
    if not isinstance(result, dict) or result.get("isError"):
        raise SmokeError(f"MCP tool failed: {result!r}")
    structured = result.get("structuredContent")
    if structured is not None:
        if not isinstance(structured, dict):
            raise SmokeError("MCP structuredContent is not an object")
        return structured
    content = result.get("content")
    if (
        not isinstance(content, list) or len(content) != 1
        or not isinstance(content[0], dict) or content[0].get("type") != "text"
        or not isinstance(content[0].get("text"), str)
    ):
        raise SmokeError("MCP tool did not return one JSON text block")
    try:
        payload = json.loads(content[0]["text"])
    except json.JSONDecodeError as exc:
        raise SmokeError("MCP tool returned invalid JSON text") from exc
    if not isinstance(payload, dict):
        raise SmokeError("MCP tool returned a non-object JSON value")
    return payload


def _assert_explanation(payload: dict, did: str, expected: str) -> None:
    """Require an actual successful explanation matching the shipped wheel, not just discovery."""
    if (
        payload.get("found") is not True
        or payload.get("detection_id") != did
        or payload.get("doc_path") != f"docs/detector-methodology/{did.lower()}.md"
        or payload.get("methodology") != expected
    ):
        raise SmokeError(f"MCP explanation for {did} does not match the wheel methodology")


def _smoke_mcp(coda: Path, workdir: Path, methodology: dict[str, str]) -> list[str]:
    """Call the installed catalog and every explanation outside a checkout, without Azure reads."""
    stderr_path = workdir / "mcp-stderr.log"
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [str(coda), "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            cwd=workdir,
        )
        if process.stdin is None or process.stdout is None:
            raise SmokeError("failed to open MCP stdio pipes")
        messages: queue.Queue[object] = queue.Queue()
        threading.Thread(target=_reader, args=(process.stdout, messages), daemon=True).start()
        try:
            _write_jsonrpc(
                process.stdin,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "coda-artifact-smoke", "version": "1"},
                    },
                },
            )
            initialized = _response(messages, 1)
            result = initialized.get("result", {})
            if result.get("serverInfo", {}).get("name") != "coda":
                raise SmokeError(f"unexpected MCP serverInfo: {result.get('serverInfo')!r}")
            if not result.get("protocolVersion"):
                raise SmokeError("MCP initialize response omitted protocolVersion")
            _write_jsonrpc(
                process.stdin,
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            )
            _write_jsonrpc(
                process.stdin,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            listed = _response(messages, 2).get("result", {}).get("tools", [])
            if not isinstance(listed, list):
                raise SmokeError("MCP tools/list did not return a list")
            names = {
                tool["name"] for tool in listed
                if isinstance(tool, dict) and isinstance(tool.get("name"), str)
            }
            if "update" in names:
                raise SmokeError("packaged MCP tools/list exposed forbidden update tool")
            if names != _EXPECTED_TOOLS or len(listed) != len(names):
                raise SmokeError(f"unexpected MCP tool catalog: {sorted(map(str, names))}")
            request_id = 2

            def call(name: str, arguments: dict) -> dict:
                """Send one sequential offline tool call and require a successful object result."""
                nonlocal request_id
                request_id += 1
                _write_jsonrpc(process.stdin, {
                    "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                })
                return _tool_payload(_response(messages, request_id))

            catalog = call("list_detectors", {})
            detectors = catalog.get("detectors")
            if not isinstance(detectors, list):
                raise SmokeError("MCP detector catalog is not a list")
            ids = {
                item["detection_id"] for item in detectors
                if isinstance(item, dict) and isinstance(item.get("detection_id"), str)
            }
            if (
                ids != _EXPECTED_DETECTORS or catalog.get("count") != len(ids)
                or len(detectors) != len(ids) or set(methodology) != ids
            ):
                raise SmokeError("MCP detector catalog does not match the shipped methodology")
            for did in sorted(ids):
                payload = call("explain_finding", {"detection_id": did})
                _assert_explanation(payload, did, methodology[did])
            unknown = call("explain_finding", {"detection_id": "DX-999"})
            if unknown.get("found") is not False or unknown.get("detection_id") != "DX-999":
                raise SmokeError("MCP unknown detector did not return the not-found contract")
            return sorted(name for name in names if isinstance(name, str))
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait(timeout=10)
                raise SmokeError("MCP server did not exit within 10s after stdin closed") from exc


def run_smoke(
    dist: Path,
    workdir: Path,
    *,
    no_constraints: bool = False,
    keep_venvs: bool = False,
    wheelhouse: Path | None = None,
) -> dict:
    """Install and exercise the exact artifact, writing a machine-readable result."""
    dist = dist.resolve()
    workdir = workdir.resolve()
    if wheelhouse is not None:
        wheelhouse = wheelhouse.resolve()
        if no_constraints:
            raise SmokeError("--wheelhouse requires the locked runtime/MCP constraints")
        if not wheelhouse.is_dir():
            raise SmokeError(f"wheelhouse is not a directory: {wheelhouse}")
    wheel = find_single_wheel(dist)
    methodology = assert_wheel_contents(wheel)
    runtime_constraint, mcp_constraint = constraint_paths(dist, no_constraints=no_constraints)
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    web_root = workdir / "web-venv"
    mcp_root = workdir / "mcp-venv"
    result: dict = {
        "wheel": str(wheel),
        "public_index": {},
        "web": {},
        "mcp": {},
    }
    try:
        if wheelhouse is None:
            result["public_index"] = preflight_public_index()
        else:
            result["public_index"] = {
                "mode": "offline-wheelhouse",
                "public_cdn_validated": False,
            }
        web_python, web_coda = _create_venv(web_root)
        result["web"]["interpreter"] = str(web_python.resolve())
        _install(
            web_python,
            str(wheel),
            runtime_constraint,
            wheelhouse=wheelhouse,
        )
        _assert_private_imports_absent(web_python, workdir)
        if not web_coda.is_file():
            raise SmokeError(f"installed coda launcher missing: {web_coda}")

        port = find_free_port()
        web_log = workdir / "web.log"
        with web_log.open("wb") as log:
            web_process = subprocess.Popen(
                [str(web_coda), "web", "--host", "127.0.0.1", "--port", str(port)],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            result["web"]["pid"] = web_process.pid
            try:
                body = _poll_web(port, web_process)
                if "generateLoad" in body:
                    raise SmokeError("public web response exposed forbidden generateLoad control")
                result["web"]["http_status"] = 200
            finally:
                _stop_process(web_process)
        missing_extra = subprocess.run(
            [str(web_coda), "mcp"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if not matches_missing_extra_message(missing_extra):
            raise SmokeError(
                "web-only coda mcp did not fail with the required coda[mcp] @ guidance"
            )
        result["web"]["missing_extra_exit"] = missing_extra.returncode

        mcp_python, mcp_coda = _create_venv(mcp_root)
        result["mcp"]["interpreter"] = str(mcp_python.resolve())
        requirement = f"coda[mcp] @ {wheel.as_uri()}"
        _install(
            mcp_python,
            requirement,
            mcp_constraint,
            wheelhouse=wheelhouse,
        )
        if not mcp_coda.is_file():
            raise SmokeError(f"installed coda launcher missing: {mcp_coda}")
        result["mcp"]["tools"] = _smoke_mcp(mcp_coda, workdir, methodology)
        result["mcp"]["explained_detectors"] = sorted(methodology)
        result["mcp"]["methodology_sha256"] = {
            did: hashlib.sha256(text.encode("utf-8")).hexdigest()
            for did, text in sorted(methodology.items())
        }
        result["ok"] = True
        return result
    finally:
        (workdir / "smoke-result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not keep_venvs:
            shutil.rmtree(web_root, ignore_errors=True)
            shutil.rmtree(mcp_root, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    """Build the cross-platform artifact-smoke command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--no-constraints", action="store_true")
    parser.add_argument("--keep-venvs", action="store_true")
    parser.add_argument(
        "--wheelhouse",
        type=Path,
        help=(
            "install dependencies strictly offline from this caller-populated directory; "
            "locked constraints remain required"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the smoke and return one on any validation or subprocess failure."""
    args = _parser().parse_args(argv)
    try:
        result = run_smoke(
            args.dist,
            args.workdir,
            no_constraints=args.no_constraints,
            keep_venvs=args.keep_venvs,
            wheelhouse=args.wheelhouse,
        )
    except (OSError, SmokeError, subprocess.SubprocessError) as exc:
        print(f"artifact smoke failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

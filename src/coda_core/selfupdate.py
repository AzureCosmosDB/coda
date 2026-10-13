"""Self-update for a public-release source checkout (CLI + internal MCP shim).

The source distribution is a git clone of the public release repo
(github.com/AzureCosmosDB/coda). To stop customers running stale source checkouts -- and giving
feedback on old behavior -- CODA checks for a newer version on every run and, if its checkout is
behind, updates itself in place (``git pull`` + ``uv sync``) and re-execs with the new code.

Faithful to cosmic-kusto's proven check: compare ``APP_VERSION`` with PEP 440 semantics and update only
when **strictly behind** (never clobber an ahead/dev checkout). We read the remote version with git
(``git show origin/main:...``) rather than the raw CDN, because the checkout already carries any
required git authentication and git is always present in a source checkout.

Safety (self-update must never break the tool — it is best-effort and fail-open):
* **Only the public-release checkout updates** -- gated on the ``origin`` remote being the public
  release repo, so a developer's internal checkout is never touched.
* **Fail-open** — any problem (offline, not a git repo, dirty tree, fetch/pull/sync error) prints a
  short note to stderr and runs the CURRENT version.
* **Opt out** with ``CODA_NO_AUTO_UPDATE=1``; the re-exec sets a guard env so an update can't loop.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from coda_core import APP_VERSION

# Only a checkout whose origin is this repo auto-updates (keeps internal/dev checkouts untouched).
PUBLIC_RELEASE_REMOTE = "AzureCosmosDB/coda"
_DISABLE_ENV = "CODA_NO_AUTO_UPDATE"
_GUARD_ENV = "CODA_SELF_UPDATED"  # set before re-exec so the relaunched process skips the check
_FETCH_TIMEOUT_S = 12
_PULL_TIMEOUT_S = 60
_SYNC_TIMEOUT_S = 300


def _eprint(msg: str) -> None:
    # Notifications go to STDERR so they never corrupt CLI report stdout or the MCP stdio protocol.
    print(msg, file=sys.stderr, flush=True)


def _repo_root() -> Path | None:
    """The git checkout root containing this package, or None if not a git checkout."""
    for parent in Path(__file__).resolve().parents:
        if (parent / ".git").exists():
            return parent
    return None


def _git(root: Path, *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, timeout=timeout,
    )


def _is_public_release_clone(root: Path) -> bool:
    """True only for the public release repo -- never auto-update an internal/dev checkout."""
    try:
        r = _git(root, "remote", "get-url", "origin", timeout=10)
    except Exception:  # noqa: BLE001 - any git failure means this is not a release checkout
        return False
    return (
        r.returncode == 0
        and PUBLIC_RELEASE_REMOTE.lower() in (r.stdout or "").strip().lower()
    )


def _parse_version(text: str) -> str | None:
    m = re.search(r'APP_VERSION\s*=\s*["\']([^"\']+)["\']', text or "")
    return m.group(1) if m else None


def is_behind(local: str, remote: str) -> bool:
    """True iff ``local`` is STRICTLY older than ``remote`` (PEP 440; tuple-of-ints fallback)."""
    try:
        from packaging.version import Version
        return Version(local) < Version(remote)
    except Exception:  # noqa: BLE001 - non-PEP440 strings or packaging missing -> naive compare
        def _t(v: str) -> tuple[int, ...]:
            return tuple(int("".join(c for c in p if c.isdigit()) or 0) for p in v.split("."))
        return _t(local) < _t(remote)


def remote_version(root: Path) -> str | None:
    """Fetch and return the upstream ``APP_VERSION``, or None if it can't be read (offline/auth)."""
    fetch = _git(root, "fetch", "--quiet", "origin", "main", timeout=_FETCH_TIMEOUT_S)
    if fetch.returncode != 0:
        return None
    show = _git(root, "show", "origin/main:src/coda_core/__init__.py", timeout=15)
    if show.returncode != 0:
        return None
    return _parse_version(show.stdout)


def perform_update(root: Path, *, notify=_eprint) -> tuple[bool, str]:
    """``git pull --ff-only`` + ``uv sync``. Returns ``(ok, message)``; refuses a dirty tree."""
    dirty = _git(root, "status", "--porcelain", timeout=15)
    if dirty.returncode == 0 and dirty.stdout.strip():
        return False, "local changes present — run `git stash && git pull && uv sync` yourself"
    pull = _git(root, "pull", "--ff-only", "origin", "main", timeout=_PULL_TIMEOUT_S)
    if pull.returncode != 0:
        return False, f"git pull failed: {(pull.stderr or '').strip()[:200]}"
    try:
        subprocess.run(
            ["uv", "sync", "--quiet"], cwd=str(root),
            capture_output=True, text=True, timeout=_SYNC_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001 - uv sync is best-effort; code already updated
        notify(f"[CODA] dependency sync warning: {type(exc).__name__} (continuing)")
    return True, "updated"


def auto_update(*, notify=_eprint, reexec: bool = True) -> None:
    """Update an older public-release checkout in place and re-exec; best-effort and fail-open.

    Called at the start of each CLI run and at MCP-server startup. After a successful update it re-execs
    the same command (``sys.argv``) so the run proceeds on the new code; the guard env prevents a loop.
    """
    if os.environ.get(_DISABLE_ENV) or os.environ.get(_GUARD_ENV):
        return
    try:
        root = _repo_root()
        if root is None or not _is_public_release_clone(root):
            return  # not the public release checkout -- never touch an internal/dev checkout
        remote = remote_version(root)
        if not remote or not is_behind(APP_VERSION, remote):
            return  # up to date, or offline (fail-open)
        notify(f"[CODA] A newer version is available ({APP_VERSION} -> {remote}). Updating now...")
        ok, msg = perform_update(root, notify=notify)
        if not ok:
            notify(f"[CODA] Auto-update skipped: {msg}. Continuing on {APP_VERSION}.")
            return
        notify(f"[CODA] Updated to {remote}. Restarting with the new version...")
        if reexec:
            os.environ[_GUARD_ENV] = "1"
            os.execv(sys.executable, [sys.executable, *sys.argv])  # noqa: S606 - same interpreter+argv
    except Exception as exc:  # noqa: BLE001 - self-update must NEVER break the tool
        notify(f"[CODA] Update check skipped ({type(exc).__name__}). Continuing on {APP_VERSION}.")


def run_update_command(*, notify=print) -> int:
    """The explicit ``--update`` path: force a check + update, report, and do NOT re-exec.

    Returns a process exit code (0 ok). Used by the CLI ``--update`` flag and the MCP ``update`` tool,
    where the caller exits / asks the user to restart rather than re-exec mid-process.
    """
    root = _repo_root()
    if root is None or not _is_public_release_clone(root):
        notify("[CODA] Not a public-release checkout - nothing to update. Install via "
               "`git clone https://github.com/AzureCosmosDB/coda.git`.")
        return 0
    remote = remote_version(root)
    if remote is None:
        notify("[CODA] Couldn't reach the update source (offline or auth). Try `git pull && uv sync`.")
        return 1
    if not is_behind(APP_VERSION, remote):
        notify(f"[CODA] Already up to date ({APP_VERSION}).")
        return 0
    notify(f"[CODA] Updating {APP_VERSION} -> {remote}...")
    ok, msg = perform_update(root, notify=notify)
    notify(f"[CODA] {'Updated to ' + remote if ok else 'Update failed: ' + msg}.")
    return 0 if ok else 1


def update_report() -> dict:
    """Structured update result for the MCP ``update`` tool.

    Runs the same check+update as ``--update`` (no re-exec) and returns the messages plus a note that
    the MCP server must be restarted (reload the editor window) for an applied update to take effect —
    re-exec'ing mid-session would drop the client's stdio connection.
    """
    messages: list[str] = []
    code = run_update_command(notify=messages.append)
    return {
        "ok": code == 0,
        "messages": messages,
        "note": "If an update was applied, restart the CODA MCP server (reload your editor window) "
                "for the new version to take effect.",
    }


__all__ = [
    "auto_update", "run_update_command", "update_report", "perform_update", "remote_version",
    "is_behind", "PUBLIC_RELEASE_REMOTE",
]

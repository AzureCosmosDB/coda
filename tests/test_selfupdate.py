"""Unit tests for the self-update logic (pure + gated paths; no real git/network)."""

from __future__ import annotations

from pathlib import Path

import pytest

import coda_core.selfupdate as sd

pytestmark = pytest.mark.public


# --- version comparison + parsing -----------------------------------------------------

def test_is_behind_pep440():
    assert sd.is_behind("0.3.0", "0.4.0") is True
    assert sd.is_behind("0.4.0", "0.3.0") is False   # ahead -> never "behind"
    assert sd.is_behind("0.4.0", "0.4.0") is False   # equal
    assert sd.is_behind("0.3.9", "0.3.10") is True    # numeric, not lexical


def test_is_behind_non_pep440_fallback():
    # Non-PEP440 strings fall back to tuple-of-ints compare.
    assert sd.is_behind("1.2", "1.10") is True
    assert sd.is_behind("2.0", "1.9") is False


def test_parse_version_reads_app_version():
    assert sd._parse_version('APP_VERSION = "1.2.3"') == "1.2.3"
    assert sd._parse_version("APP_VERSION = '0.4.0'") == "0.4.0"
    assert sd._parse_version("nothing here") is None


# --- auto_update gating ---------------------------------------------------------------

def test_auto_update_skips_when_disabled(monkeypatch):
    monkeypatch.setenv("CODA_NO_AUTO_UPDATE", "1")
    seen: list[int] = []
    monkeypatch.setattr(sd, "_repo_root", lambda: seen.append(1))
    sd.auto_update(notify=lambda m: None)
    assert seen == []  # returned before any git work


def test_auto_update_skips_under_reexec_guard(monkeypatch):
    monkeypatch.delenv("CODA_NO_AUTO_UPDATE", raising=False)
    monkeypatch.setenv("CODA_SELF_UPDATED", "1")
    seen: list[int] = []
    monkeypatch.setattr(sd, "_repo_root", lambda: seen.append(1))
    sd.auto_update(notify=lambda m: None)
    assert seen == []


def test_auto_update_skips_non_public_release_clone(monkeypatch):
    monkeypatch.delenv("CODA_NO_AUTO_UPDATE", raising=False)
    monkeypatch.delenv("CODA_SELF_UPDATED", raising=False)
    monkeypatch.setattr(sd, "_repo_root", lambda: Path("."))
    monkeypatch.setattr(sd, "_is_public_release_clone", lambda root: False)
    pulled: list[int] = []
    monkeypatch.setattr(sd, "remote_version", lambda root: pulled.append(1))
    sd.auto_update(notify=lambda m: None)
    assert pulled == []  # never fetches/updates outside the public release checkout


def test_auto_update_skips_when_not_a_git_checkout(monkeypatch):
    monkeypatch.delenv("CODA_NO_AUTO_UPDATE", raising=False)
    monkeypatch.delenv("CODA_SELF_UPDATED", raising=False)
    monkeypatch.setattr(sd, "_repo_root", lambda: None)

    def unexpected_call(*args, **kwargs):
        raise AssertionError("packaged installs must not run subprocesses or re-exec")

    monkeypatch.setattr(sd.subprocess, "run", unexpected_call)
    monkeypatch.setattr(sd.os, "execv", unexpected_call)

    sd.auto_update(notify=lambda message: None)


def test_auto_update_updates_and_reexecs_when_behind(monkeypatch):
    monkeypatch.delenv("CODA_NO_AUTO_UPDATE", raising=False)
    monkeypatch.delenv("CODA_SELF_UPDATED", raising=False)
    monkeypatch.setattr(sd, "_repo_root", lambda: Path("."))
    monkeypatch.setattr(sd, "_is_public_release_clone", lambda root: True)
    monkeypatch.setattr(sd, "remote_version", lambda root: "999.0.0")
    monkeypatch.setattr(sd, "perform_update", lambda root, notify: (True, "updated"))
    calls: dict = {}
    monkeypatch.setattr(sd.os, "execv", lambda exe, argv: calls.setdefault("argv", argv))
    notes: list[str] = []
    sd.auto_update(notify=notes.append)
    assert "argv" in calls  # re-exec attempted with the new code
    assert any("Updated to 999.0.0" in n for n in notes)
    sd.os.environ.pop("CODA_SELF_UPDATED", None)  # don't leak the guard to other tests


def test_auto_update_fail_open_when_offline(monkeypatch):
    # remote_version None (offline / auth) => no update, no crash.
    monkeypatch.delenv("CODA_NO_AUTO_UPDATE", raising=False)
    monkeypatch.delenv("CODA_SELF_UPDATED", raising=False)
    monkeypatch.setattr(sd, "_repo_root", lambda: Path("."))
    monkeypatch.setattr(sd, "_is_public_release_clone", lambda root: True)
    monkeypatch.setattr(sd, "remote_version", lambda root: None)
    did_update: list[int] = []
    monkeypatch.setattr(sd, "perform_update", lambda root, notify: did_update.append(1))
    sd.auto_update(notify=lambda m: None)
    assert did_update == []


# --- run_update_command ---------------------------------------------------------------

def test_run_update_command_outside_public_release_clone(monkeypatch):
    monkeypatch.setattr(sd, "_repo_root", lambda: None)
    notes: list[str] = []
    code = sd.run_update_command(notify=notes.append)
    assert code == 0
    assert any("Not a public-release checkout" in n for n in notes)

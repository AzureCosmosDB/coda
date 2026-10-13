"""Local explicit-sign-in authentication for the unified CODA web application.

One ``DefaultAzureCredential`` chain is resolved lazily, only after the user selects Sign in.
Protected routes can therefore never trigger credential resolution from an idle browser tab.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from azure.identity import DefaultAzureCredential
from fastapi import HTTPException


@dataclass(frozen=True)
class LocalIdentity:
    """A resolved local credential, available only after an explicit sign-in action."""

    credential: DefaultAzureCredential


class _LocalAuthState:
    """Process-scoped explicit sign-in state for the local public web adapter.

    The local adapter serves exactly one local user from one browser tab, so sign-in state is
    process-wide rather than per-HTTP-session: there is no cookie, bearer token, tenant
    validation, or on-behalf-of exchange here. :meth:`sign_in` is only ever meant to be invoked
    by the explicit "Sign in" UI action
    (``POST /api/auth/sign-in``); nothing else in this module calls it, so no credential is ever
    built before that action is recorded.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._identity: LocalIdentity | None = None

    def sign_in(self) -> LocalIdentity:
        """Resolve (or reuse) one ``DefaultAzureCredential`` chain for this process."""
        with self._lock:
            if self._identity is None:
                self._identity = LocalIdentity(credential=DefaultAzureCredential())
            return self._identity

    def current(self) -> LocalIdentity | None:
        """Return the cached identity, or ``None`` if :meth:`sign_in` has not run yet."""
        with self._lock:
            return self._identity

    def reset(self) -> None:
        """Clear cached sign-in state; used by tests to isolate explicit-sign-in behavior."""
        with self._lock:
            self._identity = None


_STATE = _LocalAuthState()


def sign_in() -> LocalIdentity:
    """Explicit sign-in action: build (or reuse) this process's local credential.

    Call this only from the one user-initiated "Sign in" control (``POST /api/auth/sign-in``
    in :mod:`coda_web.public_app`); calling it from a dependency or background task would
    violate the explicit-action guarantee this module exists to provide.
    """
    return _STATE.sign_in()


def is_signed_in() -> bool:
    """Report sign-in state for the UI's status check, without resolving a credential."""
    return _STATE.current() is not None


def require_local_identity() -> LocalIdentity:
    """FastAPI dependency: return the signed-in local credential, or fail closed with 401.

    This never builds a credential itself -- it only returns what :func:`sign_in` already
    cached -- so no route that depends on this function can trigger background/idle credential
    resolution; every protected route 401s until the explicit sign-in action has run once.
    """
    identity = _STATE.current()
    if identity is None:
        raise HTTPException(status_code=401, detail="sign_in_required")
    return identity


def reset_for_tests() -> None:
    """Clear cached sign-in state between tests; never called by production code paths."""
    _STATE.reset()